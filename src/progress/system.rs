use anyhow::Result;
use std::thread;

use super::Reporter;
use super::render::Renderer;

pub struct System {
    reporter: Option<Reporter>,
    renderer_handle: Option<thread::JoinHandle<Result<()>>>,
}

impl Default for System {
    fn default() -> Self {
        Self::new()
    }
}

impl System {
    pub fn new() -> Self {
        let (tx, rx) = crossbeam_channel::unbounded();
        let renderer = Renderer::new(rx);

        let renderer_handle = thread::spawn(move || renderer.run());
        let reporter = Reporter::from_sender(tx);

        Self {
            reporter: Some(reporter),
            renderer_handle: Some(renderer_handle),
        }
    }

    pub fn reporter(&self) -> Reporter {
        self.reporter
            .as_ref()
            .expect("progress reporter accessed after shutdown - this is a programming error")
            .clone()
    }

    pub fn try_reporter(&self) -> Option<Reporter> {
        self.reporter.as_ref().cloned()
    }

    pub fn shutdown(mut self) -> Result<()> {
        self.close_channel();
        self.join_renderer()?;
        Ok(())
    }

    fn close_channel(&mut self) {
        if let Some(reporter) = self.reporter.take() {
            drop(reporter);
        }
    }

    fn join_renderer(&mut self) -> Result<()> {
        if let Some(handle) = self.renderer_handle.take() {
            match handle.join() {
                Ok(res) => res?,
                Err(panic) => {
                    return Err(anyhow::anyhow!(
                        "Progress renderer thread panicked: {:?}",
                        panic
                    ));
                }
            }
        }
        Ok(())
    }
}

impl Drop for System {
    fn drop(&mut self) {
        self.close_channel();
        let _ = self.join_renderer();
    }
}
