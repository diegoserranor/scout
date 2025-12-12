use std::sync::Arc;
use tokio::sync::{Semaphore, mpsc};

mod limits;

/// Helper to fan out work over targets with a tokio semaphore and a mpsc channel to receive results.
pub struct Runner<T, R> {
    targets: Vec<T>,
    tx: mpsc::Sender<R>,
    rx: mpsc::Receiver<R>,
    sem: Arc<Semaphore>,
}

impl<T, R> Runner<T, R>
where
    T: Send + 'static,
    R: Send + 'static,
{
    pub fn build(targets: Vec<T>) -> Self {
        let concurrency = limits::compute_concurrency();
        let channel_size = limits::compute_channel_size(concurrency);
        let sem = Arc::new(Semaphore::new(concurrency));
        let (tx, rx) = mpsc::channel(channel_size);

        Self {
            targets,
            tx,
            rx,
            sem,
        }
    }

    pub fn spawn<F, Fut>(self, f: F) -> mpsc::Receiver<R>
    where
        F: Fn(T) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = R> + Send + 'static,
    {
        let Runner {
            targets,
            tx,
            rx,
            sem,
        } = self;

        let f = Arc::new(f);

        for target in targets {
            let sem = sem.clone();
            let tx = tx.clone();
            let f = f.clone();

            tokio::spawn(async move {
                let _permit = sem.acquire_owned().await.unwrap();
                let result = f(target).await;
                let _ = tx.send(result).await;
            });
        }

        rx
    }
}
