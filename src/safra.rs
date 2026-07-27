// SPDX-License-Identifier: MIT
// Copyright 2026. Triad National Security, LLC.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub enum TermState {
    Idle,
    Active,
}

//Termination Detection
pub struct SafraTerminator {
    /*
    COLOR:
        White/Idle = False
        Black/Active = True
    */
    __token_state: AtomicBool,
    token_holder: AtomicUsize,
    global_done: AtomicBool,
}
impl SafraTerminator {
    pub fn new() -> Self {
        SafraTerminator {
            __token_state: AtomicBool::new(true),
            token_holder: AtomicUsize::new(0),
            global_done: AtomicBool::new(false),
        }
    }

    pub fn is_done(&self) -> bool {
        self.global_done.load(Ordering::Relaxed)
    }

    fn get_token_state(&self) -> TermState {
        match self.__token_state.load(Ordering::Relaxed) {
            true => TermState::Active,
            false => TermState::Idle,
        }
    }

    fn set_token_state(&self, state: TermState) {
        match state {
            TermState::Idle => self.__token_state.store(false, Ordering::Relaxed),
            TermState::Active => self.__token_state.store(true, Ordering::Relaxed),
        }
    }

    /// Should only return true in the event all threads are idle and the Control thread, thread 0,
    /// has set the globablly done flag to true.
    /// Otherwise it will return false in order to indicate some thread within the program is still
    /// active/working.
    pub fn check_termination(
        &self,
        thread_id: usize,
        thread_state: TermState,
        thread_count: usize,
    ) -> bool {
        if self.is_done() {
            return true;
        }

        //Control Thread
        if thread_id == 0 && self.token_holder.load(Ordering::Acquire) == 0 {
            match self.get_token_state() {
                TermState::Idle => {
                    self.global_done.store(true, Ordering::Relaxed);
                    return true;
                }
                TermState::Active => {
                    self.set_token_state(TermState::Idle);
                }
            }
        }

        //Non-Control Thread
        if self.token_holder.load(Ordering::Acquire) == thread_id {
            match thread_state {
                TermState::Idle => {}
                TermState::Active => {
                    self.set_token_state(TermState::Active);
                }
            }
            self.pass_token(thread_count, thread_id);
        }
        return false;
    }

    fn pass_token(&self, thread_count: usize, thread_id: usize) {
        self.token_holder
            .store((thread_id + 1) % thread_count, Ordering::Release);
    }
}
