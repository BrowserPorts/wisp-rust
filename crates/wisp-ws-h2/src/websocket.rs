use std::convert::Infallible;
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::Bytes;
use futures::{FutureExt, Sink, SinkExt, Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::PollSender;
use tokio_websockets::{Message, WebSocketStream};
use tracing::debug;
use wisp_wisp_server::{serve_connection, ServerContext, ServerError, WispMessage};

const ACTOR_CHANNEL_CAPACITY: usize = 16;
const INBOUND_BATCH_CAPACITY: usize = 64;
const OUTBOUND_BATCH_CAPACITY: usize = 64;

type WriteReply = Result<Vec<WispMessage>, String>;

enum WebSocketCommand {
    Write {
        messages: Vec<WispMessage>,
        reply: oneshot::Sender<WriteReply>,
    },
    Close(oneshot::Sender<Result<(), String>>),
}

#[derive(Debug)]
struct WebSocketActorError(Box<str>);

impl Display for WebSocketActorError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WebSocketActorError {}

struct ActorSink {
    sender: PollSender<WebSocketCommand>,
    pending: Vec<WispMessage>,
    write_ack: Option<oneshot::Receiver<WriteReply>>,
    close_ack: Option<oneshot::Receiver<Result<(), String>>>,
}

impl ActorSink {
    fn new(sender: mpsc::Sender<WebSocketCommand>) -> Self {
        Self {
            sender: PollSender::new(sender),
            pending: Vec::with_capacity(OUTBOUND_BATCH_CAPACITY),
            write_ack: None,
            close_ack: None,
        }
    }

    fn actor_stopped() -> WebSocketActorError {
        WebSocketActorError("websocket transport actor stopped".into())
    }

    fn map_close_reply(
        reply: Result<Result<(), String>, oneshot::error::RecvError>,
    ) -> Result<(), WebSocketActorError> {
        match reply {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(WebSocketActorError(error.into_boxed_str())),
            Err(_) => Err(Self::actor_stopped()),
        }
    }

    fn poll_write_ack(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), WebSocketActorError>> {
        let Some(ack) = self.write_ack.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let reply = ready!(Pin::new(ack).poll(cx));
        self.write_ack = None;
        match reply {
            Ok(Ok(messages)) => {
                self.pending = messages;
                Poll::Ready(Ok(()))
            }
            Ok(Err(error)) => Poll::Ready(Err(WebSocketActorError(error.into_boxed_str()))),
            Err(_) => Poll::Ready(Err(Self::actor_stopped())),
        }
    }

    fn poll_dispatch(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), WebSocketActorError>> {
        ready!(self.poll_write_ack(cx))?;
        if self.pending.is_empty() {
            return Poll::Ready(Ok(()));
        }
        ready!(Pin::new(&mut self.sender).poll_ready(cx)).map_err(|_| Self::actor_stopped())?;
        let (tx, rx) = oneshot::channel();
        let messages = std::mem::take(&mut self.pending);
        Pin::new(&mut self.sender)
            .start_send(WebSocketCommand::Write {
                messages,
                reply: tx,
            })
            .map_err(|_| Self::actor_stopped())?;
        self.write_ack = Some(rx);
        self.poll_write_ack(cx)
    }
}

impl Sink<WispMessage> for ActorSink {
    type Error = WebSocketActorError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.poll_write_ack(cx))?;
        if self.pending.len() < OUTBOUND_BATCH_CAPACITY {
            Poll::Ready(Ok(()))
        } else {
            self.poll_dispatch(cx)
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: WispMessage) -> Result<(), Self::Error> {
        if self.pending.len() >= OUTBOUND_BATCH_CAPACITY {
            return Err(WebSocketActorError("websocket batch is full".into()));
        }
        self.pending.push(item);
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.poll_dispatch(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.close_ack.is_none() {
            ready!(self.as_mut().poll_flush(cx))?;
            ready!(Pin::new(&mut self.sender).poll_ready(cx)).map_err(|_| Self::actor_stopped())?;
            let (tx, rx) = oneshot::channel();
            Pin::new(&mut self.sender)
                .start_send(WebSocketCommand::Close(tx))
                .map_err(|_| Self::actor_stopped())?;
            self.close_ack = Some(rx);
        }
        let reply = ready!(Pin::new(
            self.close_ack
                .as_mut()
                .expect("close acknowledgement present")
        )
        .poll(cx));
        self.close_ack = None;
        Poll::Ready(Self::map_close_reply(reply))
    }
}

struct ActorStream {
    receiver: mpsc::Receiver<Vec<WispMessage>>,
    current: std::vec::IntoIter<WispMessage>,
}

impl ActorStream {
    fn new(receiver: mpsc::Receiver<Vec<WispMessage>>) -> Self {
        Self {
            receiver,
            current: Vec::new().into_iter(),
        }
    }
}

impl Stream for ActorStream {
    type Item = Result<WispMessage, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(message) = self.current.next() {
                return Poll::Ready(Some(Ok(message)));
            }
            match Pin::new(&mut self.receiver).poll_recv(cx) {
                Poll::Ready(Some(messages)) => self.current = messages.into_iter(),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn to_websocket_message(message: WispMessage) -> Message {
    match message {
        WispMessage::Binary(bytes) => Message::binary(bytes),
        WispMessage::Text(text) => Message::text(text),
    }
}

fn from_websocket_message(message: Message) -> Option<WispMessage> {
    if message.is_binary() {
        let bytes: Bytes = message.into_payload().into();
        Some(WispMessage::Binary(bytes))
    } else if message.is_text() {
        message
            .as_text()
            .map(|text| WispMessage::Text(text.to_owned()))
    } else {
        None
    }
}

async fn flush_batch<T>(
    websocket: &mut WebSocketStream<T>,
    messages: &mut Vec<WispMessage>,
) -> Result<(), tokio_websockets::Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    for message in messages.drain(..) {
        websocket.feed(to_websocket_message(message)).await?;
    }
    websocket.flush().await
}

async fn handle_command<T>(
    websocket: &mut WebSocketStream<T>,
    command: Option<WebSocketCommand>,
) -> bool
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    match command {
        Some(WebSocketCommand::Write {
            mut messages,
            reply,
        }) => match flush_batch(websocket, &mut messages).await {
            Ok(()) => {
                let _ = reply.send(Ok(messages));
                true
            }
            Err(error) => {
                let _ = reply.send(Err(error.to_string()));
                false
            }
        },
        Some(WebSocketCommand::Close(reply)) => {
            let result = websocket.close().await.map_err(|error| error.to_string());
            let _ = reply.send(result);
            false
        }
        None => false,
    }
}

async fn send_incoming_batch<T>(
    websocket: &mut WebSocketStream<T>,
    commands: &mut mpsc::Receiver<WebSocketCommand>,
    incoming: &mpsc::Sender<Vec<WispMessage>>,
    messages: Vec<WispMessage>,
) -> bool
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut messages = Some(messages);
    loop {
        tokio::select! {
            biased;
            command = commands.recv() => {
                if !handle_command(websocket, command).await {
                    return false;
                }
            }
            permit = incoming.reserve() => match permit {
                Ok(permit) => {
                    permit.send(messages.take().expect("incoming batch present"));
                    return true;
                }
                Err(_) => return false,
            }
        }
    }
}

async fn drive_actor<T>(
    mut websocket: WebSocketStream<T>,
    mut commands: mpsc::Receiver<WebSocketCommand>,
    incoming: mpsc::Sender<Vec<WispMessage>>,
) -> Result<(), tokio_websockets::Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            biased;
            command = commands.recv() => {
                if !handle_command(&mut websocket, command).await {
                    return Ok(());
                }
            }
            message = websocket.next() => {
                let mut messages = Vec::with_capacity(INBOUND_BATCH_CAPACITY);
                let mut terminal = None;
                match message {
                    Some(Ok(message)) if message.is_close() => return Ok(()),
                    Some(Ok(message)) => {
                        if let Some(message) = from_websocket_message(message) {
                            messages.push(message);
                        }
                    }
                    Some(Err(error)) => return Err(error),
                    None => return Ok(()),
                }
                while messages.len() < INBOUND_BATCH_CAPACITY {
                    match websocket.next().now_or_never() {
                        Some(Some(Ok(message))) if message.is_close() => {
                            terminal = Some(Ok(()));
                            break;
                        }
                        Some(Some(Ok(message))) => {
                            if let Some(message) = from_websocket_message(message) {
                                messages.push(message);
                            }
                        }
                        Some(Some(Err(error))) => {
                            terminal = Some(Err(error));
                            break;
                        }
                        Some(None) => {
                            terminal = Some(Ok(()));
                            break;
                        }
                        None => break,
                    }
                }
                if !messages.is_empty()
                    && !send_incoming_batch(&mut websocket, &mut commands, &incoming, messages).await
                {
                    return Ok(());
                }
                if let Some(result) = terminal {
                    return result;
                }
            }
        }
    }
}

pub async fn serve_websocket<T>(
    websocket: WebSocketStream<T>,
    server_ctx: ServerContext,
) -> Result<(), ServerError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (command_tx, command_rx) = mpsc::channel(ACTOR_CHANNEL_CAPACITY);
    let (incoming_tx, incoming_rx) = mpsc::channel(ACTOR_CHANNEL_CAPACITY);
    let actor = tokio::spawn(drive_actor(websocket, command_rx, incoming_tx));
    let result = serve_connection(
        ActorSink::new(command_tx),
        ActorStream::new(incoming_rx),
        server_ctx,
    )
    .await;
    match actor.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => debug!(%error, "websocket transport actor ended with error"),
        Err(error) => debug!(%error, "websocket transport actor task failed"),
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn actor_sink_dispatches_one_acknowledged_batch() {
        let (command_tx, mut command_rx) = mpsc::channel(ACTOR_CHANNEL_CAPACITY);
        let actor = tokio::spawn(async move {
            let Some(WebSocketCommand::Write {
                mut messages,
                reply,
            }) = command_rx.recv().await
            else {
                panic!("expected write batch");
            };
            assert_eq!(messages.len(), 3);
            let capacity = messages.capacity();
            messages.clear();
            reply.send(Ok(messages)).expect("sink receives reply");
            capacity
        });

        let mut sink = ActorSink::new(command_tx);
        sink.feed(WispMessage::Binary(Bytes::from_static(b"one")))
            .await
            .expect("feed one");
        sink.feed(WispMessage::Binary(Bytes::from_static(b"two")))
            .await
            .expect("feed two");
        sink.feed(WispMessage::Binary(Bytes::from_static(b"three")))
            .await
            .expect("feed three");
        sink.flush().await.expect("flush batch");

        let capacity = actor.await.expect("actor task");
        assert_eq!(sink.pending.capacity(), capacity);
        assert!(sink.pending.is_empty());
    }

    #[tokio::test]
    async fn actor_stream_preserves_batched_message_order() {
        let (tx, rx) = mpsc::channel(ACTOR_CHANNEL_CAPACITY);
        tx.send(vec![
            WispMessage::Binary(Bytes::from_static(b"one")),
            WispMessage::Binary(Bytes::from_static(b"two")),
        ])
        .await
        .expect("send batch");
        drop(tx);

        let mut stream = ActorStream::new(rx);
        for expected in [b"one".as_slice(), b"two".as_slice()] {
            let message = stream
                .next()
                .await
                .expect("message")
                .expect("infallible stream");
            let WispMessage::Binary(bytes) = message else {
                panic!("expected binary message");
            };
            assert_eq!(bytes.as_ref(), expected);
        }
        assert!(stream.next().await.is_none());
    }
}
