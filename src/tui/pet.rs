use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::cli::Mode;

const SLEEP_AFTER: Duration = Duration::from_secs(45);
const DECAY_EVERY: Duration = Duration::from_secs(12);
const RECHARGE_EVERY: Duration = Duration::from_secs(2);
const CHATTER_MIN_SECS: u64 = 8;
const CHATTER_JITTER_SECS: u64 = 6;
const TYPE_SPEED: u64 = 2;

const INITIAL_HAPPINESS: u8 = 80;
const INITIAL_ENERGY: u8 = 90;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Stat(u8);

impl Stat {
    const MAX: u8 = 100;
    const LOW_THRESHOLD: u8 = 25;

    const fn new(value: u8) -> Self {
        if value > Self::MAX {
            Self(Self::MAX)
        } else {
            Self(value)
        }
    }

    pub const fn get(self) -> u8 {
        self.0
    }

    pub const fn is_low(self) -> bool {
        self.0 < Self::LOW_THRESHOLD
    }

    pub const fn is_full(self) -> bool {
        self.0 >= Self::MAX
    }

    fn add(&mut self, delta: u8) {
        self.0 = self.0.saturating_add(delta).min(Self::MAX);
    }

    fn sub(&mut self, delta: u8) {
        self.0 = self.0.saturating_sub(delta);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mood {
    Idle,
    Working,
    Happy,
    Loved,
    Eating,
    Startled,
    Sleepy,
    Hungry,
    Sad,
}

impl Mood {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Idle => "content",
            Self::Working => "focused",
            Self::Happy => "overjoyed",
            Self::Loved => "smitten",
            Self::Eating => "munching",
            Self::Startled => "spooked",
            Self::Sleepy => "snoozing",
            Self::Hungry => "peckish",
            Self::Sad => "lonely",
        }
    }
}

struct Rng(u64);

impl Rng {
    fn from_clock() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0x9e37_79b9_7f4a_7c15, |d| {
                d.as_secs() ^ (u64::from(d.subsec_nanos()) << 32)
            });
        // xorshift64 stalls at 0, so keep the low bit set
        Self(seed | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn pick(&mut self, lines: &[&'static str], avoid: &str) -> &'static str {
        let len = lines.len();
        let idx = usize::try_from(self.next() % (len as u64)).unwrap_or(0);
        if lines[idx] == avoid && len > 1 {
            lines[(idx + 1) % len]
        } else {
            lines[idx]
        }
    }
}

pub struct Pet {
    mood: Mood,
    happiness: Stat,
    energy: Stat,
    sealed: u32,
    opened: u32,
    tick: u64,
    speech: &'static str,
    speech_tick: u64,
    reaction_until: Option<Instant>,
    last_input: Instant,
    last_stat_change: Instant,
    next_chatter: Instant,
    born: Instant,
    rng: Rng,
}

impl Pet {
    pub fn new(now: Instant) -> Self {
        Self {
            mood: Mood::Idle,
            happiness: Stat::new(INITIAL_HAPPINESS),
            energy: Stat::new(INITIAL_ENERGY),
            sealed: 0,
            opened: 0,
            tick: 0,
            speech: "hi! i'm ferris, your file guardian",
            speech_tick: 0,
            reaction_until: None,
            last_input: now,
            last_stat_change: now,
            next_chatter: now + Duration::from_secs(10),
            born: now,
            rng: Rng::from_clock(),
        }
    }

    pub const fn mood(&self) -> Mood {
        self.mood
    }

    pub const fn happiness(&self) -> Stat {
        self.happiness
    }

    pub const fn energy(&self) -> Stat {
        self.energy
    }

    pub const fn sealed(&self) -> u32 {
        self.sealed
    }

    pub const fn opened(&self) -> u32 {
        self.opened
    }

    pub const fn tick(&self) -> u64 {
        self.tick
    }

    // returns the current line and how many chars the typewriter has revealed
    pub fn speech(&self) -> (&'static str, usize) {
        let shown = self
            .tick
            .saturating_sub(self.speech_tick)
            .saturating_add(1)
            .saturating_mul(TYPE_SPEED);
        (self.speech, usize::try_from(shown).unwrap_or(usize::MAX))
    }

    pub fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.born)
    }

    pub fn say(&mut self, line: &'static str) {
        self.speech = line;
        self.speech_tick = self.tick;
    }

    fn react(&mut self, mood: Mood, duration: Duration, line: &'static str, now: Instant) {
        self.mood = mood;
        self.reaction_until = Some(now + duration);
        self.say(line);
    }

    pub fn notice_input(&mut self, now: Instant) {
        if self.mood == Mood::Sleepy {
            self.mood = Mood::Idle;
            self.say("*yawn*... oh! hi there~");
            self.next_chatter = now + Duration::from_secs(CHATTER_MIN_SECS);
        }
        self.last_input = now;
    }

    pub fn update(&mut self, now: Instant, tick: u64, working: bool) {
        self.tick = tick;

        let reacting = self.reaction_until.is_some_and(|until| now < until);
        if !reacting {
            self.reaction_until = None;
        }

        let calm = !working && !reacting;
        let asleep = calm && now.saturating_duration_since(self.last_input) >= SLEEP_AFTER;
        self.tick_stats(now, asleep, working);

        let next = self.resolve_mood(working, reacting, asleep);
        if next != self.mood {
            self.mood = next;
            if calm {
                self.chatter(now);
            }
        } else if calm && now >= self.next_chatter {
            self.chatter(now);
        }
    }

    const fn resolve_mood(&self, working: bool, reacting: bool, asleep: bool) -> Mood {
        if working {
            Mood::Working
        } else if reacting {
            self.mood
        } else if asleep {
            Mood::Sleepy
        } else if self.happiness.is_low() {
            Mood::Sad
        } else if self.energy.is_low() {
            Mood::Hungry
        } else {
            Mood::Idle
        }
    }

    fn tick_stats(&mut self, now: Instant, asleep: bool, working: bool) {
        let since = now.saturating_duration_since(self.last_stat_change);
        if working {
            self.last_stat_change = now;
        } else if asleep {
            if since >= RECHARGE_EVERY {
                self.energy.add(1);
                self.last_stat_change = now;
            }
        } else if since >= DECAY_EVERY {
            self.happiness.sub(1);
            self.energy.sub(1);
            self.last_stat_change = now;
        }
    }

    fn chatter(&mut self, now: Instant) {
        let lines = match self.mood {
            Mood::Sleepy => SLEEPY_LINES,
            Mood::Hungry => HUNGRY_LINES,
            Mood::Sad => SAD_LINES,
            _ => IDLE_LINES,
        };
        let line = self.rng.pick(lines, self.speech);
        self.say(line);
        let jitter = self.rng.next() % CHATTER_JITTER_SECS;
        self.next_chatter = now + Duration::from_secs(CHATTER_MIN_SECS + jitter);
    }

    pub fn feed(&mut self, now: Instant) {
        if self.energy.is_full() {
            self.happiness.add(1);
            self.react(
                Mood::Happy,
                Duration::from_secs(2),
                "i'm stuffed! maybe later~",
                now,
            );
            return;
        }

        self.energy.add(18);
        self.happiness.add(4);
        let line = self.rng.pick(SNACK_LINES, self.speech);
        self.react(Mood::Eating, Duration::from_millis(2500), line, now);
    }

    pub fn pet(&mut self, now: Instant) {
        self.happiness.add(15);
        let line = if self.happiness.is_full() {
            "maximum crab joy achieved!!"
        } else {
            self.rng.pick(PET_LINES, self.speech)
        };
        self.react(Mood::Loved, Duration::from_secs(3), line, now);
    }

    pub fn start_work(&mut self, mode: Mode) {
        self.mood = Mood::Working;
        self.reaction_until = None;
        self.say(match mode {
            Mode::Encrypt => "crunching argon2id + aes-256-gcm...",
            Mode::Decrypt => "verifying tag & unlocking...",
        });
    }

    pub fn work_succeeded(&mut self, mode: Mode, now: Instant) {
        self.happiness.add(10);
        self.energy.sub(6);
        let line = match mode {
            Mode::Encrypt => {
                self.sealed = self.sealed.saturating_add(1);
                self.rng.pick(SEALED_LINES, self.speech)
            }
            Mode::Decrypt => {
                self.opened = self.opened.saturating_add(1);
                self.rng.pick(OPENED_LINES, self.speech)
            }
        };
        self.react(Mood::Happy, Duration::from_secs(4), line, now);
    }

    pub fn work_failed(&mut self, now: Instant) {
        self.happiness.sub(8);
        let line = self.rng.pick(OOPS_LINES, self.speech);
        self.react(Mood::Startled, Duration::from_secs(4), line, now);
    }
}

const IDLE_LINES: &[&str] = &[
    "click-clack... standing by",
    "your secrets are safe with me",
    "no unsafe blocks in this shell!",
    "argon2id makes brute-forcers cry",
    "*polishes shell* ...pristine",
    "fresh nonces every time, promise",
    "the borrow checker approves of you",
    "psst... ^P for zero-cost cuddles",
    "i dream in 256-bit keys",
    "*scuttles sideways contentedly*",
];
const HUNGRY_LINES: &[&str] = &[
    "my tummy is rumbling... ^F?",
    "could really go for some bytes",
    "running low on crab fuel...",
];
const SAD_LINES: &[&str] = &[
    "i feel a little lonely... ^P?",
    "*sad clicking noises*",
    "nobody pets the crab anymore",
];
const SLEEPY_LINES: &[&str] = &[
    "zzz... nonces... zzz",
    "zzz... *mumbles about ciphers*",
    "z z z... (press any key)",
];
const SNACK_LINES: &[&str] = &[
    "nom nom! crunchy memory-safe bytes",
    "mmm... freshly salted hashes",
    "*crunch* tastes like zero-copy",
];
const PET_LINES: &[&str] = &[
    "*happy crab noises* <3",
    "hehe, that tickles my shell!",
    "clack clack! more pats pls",
];
const SEALED_LINES: &[&str] = &[
    "sealed tight with aes-256-gcm!",
    "locked up! not even i can peek",
];
const OPENED_LINES: &[&str] = &["tag verified & unlocked!", "integrity check passed, enjoy!"];
const OOPS_LINES: &[&str] = &["oh snap! something went wrong", "eek! that didn't work out"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interactions_update_state() {
        let now = Instant::now();
        let mut pet = Pet::new(now);
        pet.energy = Stat::new(50);
        pet.happiness = Stat::new(50);

        pet.feed(now);
        assert!(pet.energy().get() > 50);
        assert_eq!(pet.mood(), Mood::Eating);

        pet.pet(now);
        assert!(pet.happiness().get() > 54);
        assert_eq!(pet.mood(), Mood::Loved);
    }

    #[test]
    fn feeding_when_full_is_refused() {
        let now = Instant::now();
        let mut pet = Pet::new(now);
        pet.energy = Stat::new(Stat::MAX);

        pet.feed(now);
        assert_eq!(pet.energy().get(), Stat::MAX);
        assert_eq!(pet.mood(), Mood::Happy);
    }

    #[test]
    fn reactions_expire_deterministically() {
        let start = Instant::now();
        let mut pet = Pet::new(start);

        pet.pet(start);
        assert_eq!(pet.mood(), Mood::Loved);

        pet.update(start + Duration::from_secs(2), 1, false);
        assert_eq!(pet.mood(), Mood::Loved);

        pet.update(start + Duration::from_secs(4), 2, false);
        assert_eq!(pet.mood(), Mood::Idle);
    }

    #[test]
    fn falls_asleep_and_wakes_up() {
        let start = Instant::now();
        let mut pet = Pet::new(start);
        pet.energy = Stat::new(50);

        let later = start + SLEEP_AFTER + RECHARGE_EVERY;
        pet.update(later, 1, false);
        assert_eq!(pet.mood(), Mood::Sleepy);
        assert!(pet.energy().get() > 50);

        pet.notice_input(later);
        pet.update(later, 2, false);
        assert_eq!(pet.mood(), Mood::Idle);
    }

    #[test]
    fn low_stats_change_mood() {
        let now = Instant::now();
        let mut pet = Pet::new(now);
        pet.happiness = Stat::new(10);
        pet.update(now, 1, false);
        assert_eq!(pet.mood(), Mood::Sad);

        pet.happiness = Stat::new(80);
        pet.energy = Stat::new(10);
        pet.update(now, 2, false);
        assert_eq!(pet.mood(), Mood::Hungry);
    }

    #[test]
    fn work_cycle_counts_jobs() {
        let now = Instant::now();
        let mut pet = Pet::new(now);
        pet.start_work(Mode::Encrypt);
        pet.update(now, 1, true);
        assert_eq!(pet.mood(), Mood::Working);

        pet.work_succeeded(Mode::Encrypt, now);
        pet.update(now, 2, false);
        assert_eq!(pet.mood(), Mood::Happy);
        assert_eq!(pet.sealed(), 1);
    }

    #[test]
    fn speech_reveals_over_time() {
        let now = Instant::now();
        let mut pet = Pet::new(now);
        pet.update(now, 10, false);
        pet.say("hello");
        assert_eq!(pet.speech().1, 2);
        pet.update(now, 12, false);
        assert_eq!(pet.speech().1, 6);
    }
}
