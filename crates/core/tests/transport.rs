#![allow(clippy::unwrap_used, reason = "direct regression observations")]
use futures::{FutureExt, channel::oneshot, future::BoxFuture};
use mpz_common::{
    Context, Session, ThreadPool, ThreadPoolBuildError,
    context::{ContextError, DEFAULT_CONCURRENCY_LIMIT},
    mux::test_framed_mux,
};
use std::{
    collections::HashSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    task::{Poll, Waker},
    time::Duration,
};
mod support;

// Policy: lifecycle regressions must terminate even when worker teardown is broken.
const DEADLINE: Duration = Duration::from_secs(30);

fn mapped(length: usize) {
    futures::executor::block_on(async {
        let (mux, _peer) = test_framed_mux(1);
        let session = Session::builder().cooperative().build(mux).unwrap();
        let mut context = session.new_context().unwrap();
        let started = Arc::new(AtomicUsize::new(0));
        let (senders, receivers): (Vec<_>, Vec<_>) =
            (0..length).map(|_| oneshot::channel::<()>()).unzip();
        let count = started.clone();
        let mut task = context
            .map(
                receivers.into_iter().enumerate().collect(),
                move |ctx, (index, ready)| {
                    count.fetch_add(1, Ordering::SeqCst);
                    let id = ctx.id().as_ref().to_vec();
                    async move {
                        ready.await.unwrap();
                        (index, id)
                    }
                    .boxed()
                },
            )
            .boxed();
        if length > 0 {
            assert!(futures::poll!(&mut task).is_pending());
        }
        assert_eq!(
            started.load(Ordering::SeqCst),
            length.min(DEFAULT_CONCURRENCY_LIMIT)
        );
        for sender in senders {
            sender.send(()).unwrap();
        }
        let output = task.await.unwrap();
        assert_eq!(
            output.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
            (0..length).collect::<Vec<_>>()
        );
        assert_eq!(
            output
                .into_iter()
                .map(|(_, id)| id)
                .collect::<HashSet<_>>()
                .len(),
            length.min(DEFAULT_CONCURRENCY_LIMIT)
        );
    });
}
#[test]
fn bounded_map_preserves_order_and_bounds_channels() {
    for length in 0..256 {
        mapped(length);
    }
}

struct Dropped(mpsc::Sender<()>);
impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.send(()).unwrap();
    }
}

#[derive(Clone, Copy)]
enum Operation {
    Map,
    Join,
    TryJoin,
    TryJoin3,
    TryJoin4,
}
impl Operation {
    fn count(self) -> usize {
        match self {
            Self::Map | Self::Join | Self::TryJoin => 2,
            Self::TryJoin3 => 3,
            Self::TryJoin4 => 4,
        }
    }
    async fn run<F>(
        self,
        context: &mut Context,
        branch: F,
    ) -> Result<Result<Vec<usize>, usize>, ContextError>
    where
        F: for<'a> Fn(&'a mut Context, usize) -> BoxFuture<'a, Result<usize, usize>>
            + Clone
            + Send
            + 'static,
    {
        let a = branch.clone();
        let b = branch.clone();
        let c = branch.clone();
        Ok(match self {
            Self::Map => context
                .map((0..self.count()).collect(), branch)
                .await?
                .into_iter()
                .collect(),
            Self::Join => {
                let (a, b) = context
                    .join(move |ctx| a(ctx, 0), move |ctx| b(ctx, 1))
                    .await?;
                [a, b].into_iter().collect()
            }
            Self::TryJoin => context
                .try_join(move |ctx| a(ctx, 0), move |ctx| b(ctx, 1))
                .await?
                .map(|(a, b)| vec![a, b]),
            Self::TryJoin3 => context
                .try_join3(
                    move |ctx| a(ctx, 0),
                    move |ctx| b(ctx, 1),
                    move |ctx| c(ctx, 2),
                )
                .await?
                .map(|(a, b, c)| vec![a, b, c]),
            Self::TryJoin4 => context
                .try_join4(
                    move |ctx| a(ctx, 0),
                    move |ctx| b(ctx, 1),
                    move |ctx| c(ctx, 2),
                    move |ctx| branch(ctx, 3),
                )
                .await?
                .map(|(a, b, c, d)| vec![a, b, c, d]),
        })
    }
}

#[test]
fn pool_lifecycle_is_bounded() {
    support::worker("pool_worker", DEADLINE);
}

#[tokio::test]
#[ignore = "subprocess fixture; parent bounds worker joins"]
async fn pool_worker() {
    assert_eq!(std::env::var("PROOF_CLIENT_WORKER").unwrap(), "pool_worker");
    for failure in 0..3 {
        let (exited, exit) = mpsc::channel();
        let count = AtomicUsize::new(0);
        let workers = Arc::new(Mutex::new(Vec::new()));
        let handles = workers.clone();
        let result = ThreadPool::builder()
            .num_threads(3)
            .spawn(move |worker| {
                if count.fetch_add(1, Ordering::SeqCst) == failure {
                    return Err(std::io::Error::other("spawn control"));
                }
                let exited = exited.clone();
                handles.lock().unwrap().push(std::thread::spawn(move || {
                    worker();
                    exited.send(()).unwrap();
                }));
                Ok(())
            })
            .build();
        assert!(
            matches!(result, Err(ThreadPoolBuildError::Spawn(error)) if error.to_string() == "spawn control")
        );
        for _ in 0..failure {
            exit.recv_timeout(DEADLINE).unwrap();
        }
        for worker in workers.lock().unwrap().drain(..) {
            worker.join().unwrap();
        }
    }
    use Operation::*;
    for operation in [Map, Join, TryJoin, TryJoin3, TryJoin4] {
        let count = operation.count();
        for (active, wake_after_shutdown) in [(false, false), (true, false), (true, true)] {
            let (mux, _peer) = test_framed_mux(1);
            let workers = Arc::new(Mutex::new(Vec::new()));
            let handles = workers.clone();
            let pool = ThreadPool::builder()
                .num_threads(count)
                .spawn(move |worker| {
                    handles.lock().unwrap().push(std::thread::spawn(worker));
                    Ok(())
                })
                .build()
                .unwrap();
            let session = Session::builder().pool(pool.clone()).build(mux).unwrap();
            let mut context = session.new_context().unwrap();
            let (started, ready) = mpsc::channel::<Waker>();
            let (dropped, released) = mpsc::channel();
            let barrier = Arc::new(std::sync::Barrier::new(count + 1));
            let pending = barrier.clone();
            let mut task = operation
                .run(&mut context, move |_, _| {
                    let owned = Dropped(dropped.clone());
                    let mut started = Some(started.clone());
                    let pending = pending.clone();
                    futures::future::poll_fn(move |cx| {
                        let _owned = &owned;
                        if let Some(started) = started.take() {
                            started.send(cx.waker().clone()).unwrap();
                            if wake_after_shutdown {
                                pending.wait();
                                cx.waker().wake_by_ref();
                            }
                        }
                        Poll::Pending
                    })
                    .boxed()
                })
                .boxed();
            if active {
                assert!(futures::poll!(&mut task).is_pending());
                let _wakers = (0..count)
                    .map(|_| ready.recv_timeout(DEADLINE).unwrap())
                    .collect::<Vec<_>>();
                pool.shutdown();
                if wake_after_shutdown {
                    barrier.wait();
                }
            } else {
                pool.shutdown();
            }
            assert!(pool.is_shutdown());
            assert!(session.new_context().is_err());
            assert!(matches!(task.await, Err(ContextError::Cancelled)));
            for worker in workers.lock().unwrap().drain(..) {
                worker.join().unwrap();
            }
            if active {
                for _ in 0..count {
                    released.recv_timeout(DEADLINE).unwrap();
                }
            }
        }
        for failed in (0..count).map(Some).chain([None]) {
            let (mux, _peer) = test_framed_mux(1);
            let pool = ThreadPool::builder().num_threads(2).build().unwrap();
            let session = Session::builder().pool(pool.clone()).build(mux).unwrap();
            let mut context = session.new_context().unwrap();
            let (dropped, released) = mpsc::channel();
            let barrier = Arc::new(tokio::sync::Barrier::new(count));
            let cancel = failed.is_some() && matches!(operation, TryJoin | TryJoin3 | TryJoin4);
            let output = operation
                .run(&mut context, move |_, index| {
                    let owned = Dropped(dropped.clone());
                    let barrier = barrier.clone();
                    async move {
                        let _owned = owned;
                        if cancel {
                            barrier.wait().await;
                            if failed != Some(index) {
                                futures::future::pending::<()>().await;
                            }
                        }
                        if failed == Some(index) {
                            Err(index)
                        } else {
                            Ok(index)
                        }
                    }
                    .boxed()
                })
                .await
                .unwrap();
            assert_eq!(output, failed.map_or_else(|| Ok((0..count).collect()), Err));
            pool.shutdown();
            drop(session);
            drop(context);
            assert_eq!(released.into_iter().count(), count);
        }
    }
}
