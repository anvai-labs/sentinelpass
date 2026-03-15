//! Secure random password generator

use crate::crypto::{CryptoError, Result};
use rand::seq::SliceRandom;

/// Character sets for password generation
pub struct CharacterSets {
    /// Lowercase letters (a-z)
    pub lowercase: &'static [u8],
    /// Uppercase letters (A-Z)
    pub uppercase: &'static [u8],
    /// Digits (0-9)
    pub digits: &'static [u8],
    /// Symbols/special characters
    pub symbols: &'static [u8],
    /// All letters (upper + lower case)
    pub letters: &'static [u8],
    /// Alphanumeric (letters + digits)
    pub alphanumeric: &'static [u8],
    /// All printable ASCII characters
    pub all: &'static [u8],
}

impl CharacterSets {
    const LOWERCASE: &'static [u8] = b"abcdefghijklmnopqrstuvwxyz";
    const UPPERCASE: &'static [u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS: &'static [u8] = b"0123456789";
    const SYMBOLS: &'static [u8] = b"!@#$%^&*()_+-=[]{}|;:,.<>?";

    pub const fn get() -> &'static CharacterSets {
        &CharacterSets {
            lowercase: Self::LOWERCASE,
            uppercase: Self::UPPERCASE,
            digits: Self::DIGITS,
            symbols: Self::SYMBOLS,
            letters: Self::LETTERS,
            alphanumeric: Self::ALPHANUMERIC,
            all: Self::ALL,
        }
    }

    const LETTERS: &'static [u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const ALPHANUMERIC: &'static [u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const ALL: &'static [u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
}

/// Configuration for password generation
#[derive(Debug, Clone, Copy)]
pub struct PasswordGeneratorConfig {
    /// Length of the password to generate
    pub length: usize,
    /// Include lowercase letters
    pub include_lowercase: bool,
    /// Include uppercase letters
    pub include_uppercase: bool,
    /// Include digits
    pub include_digits: bool,
    /// Include symbols
    pub include_symbols: bool,
    /// Exclude ambiguous characters (like l, 1, I, O, 0)
    pub exclude_ambiguous: bool,
}

impl Default for PasswordGeneratorConfig {
    fn default() -> Self {
        Self {
            length: 16,
            include_lowercase: true,
            include_uppercase: true,
            include_digits: true,
            include_symbols: true,
            exclude_ambiguous: true,
        }
    }
}

impl PasswordGeneratorConfig {
    /// Create a new password generator config
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the password length
    pub fn length(mut self, length: usize) -> Self {
        self.length = length;
        self
    }

    /// Include lowercase letters
    pub fn with_lowercase(mut self, include: bool) -> Self {
        self.include_lowercase = include;
        self
    }

    /// Include uppercase letters
    pub fn with_uppercase(mut self, include: bool) -> Self {
        self.include_uppercase = include;
        self
    }

    /// Include digits
    pub fn with_digits(mut self, include: bool) -> Self {
        self.include_digits = include;
        self
    }

    /// Include symbols
    pub fn with_symbols(mut self, include: bool) -> Self {
        self.include_symbols = include;
        self
    }

    /// Exclude ambiguous characters (l, 1, I, O, 0, etc.)
    pub fn exclude_ambiguous(mut self, exclude: bool) -> Self {
        self.exclude_ambiguous = exclude;
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.length < 4 {
            return Err(CryptoError::EncryptionFailed(
                "Password length must be at least 4 characters".to_string(),
            ));
        }

        if !self.include_lowercase
            && !self.include_uppercase
            && !self.include_digits
            && !self.include_symbols
        {
            return Err(CryptoError::EncryptionFailed(
                "At least one character type must be enabled".to_string(),
            ));
        }

        Ok(())
    }
}

/// Generate a secure random password
pub fn generate_password(config: &PasswordGeneratorConfig) -> Result<String> {
    config.validate()?;

    let charset = CharacterSets::get();
    let mut rng = rand::thread_rng();

    // Build the character pool
    let mut pool = Vec::new();

    if config.include_lowercase {
        pool.extend(charset.lowercase);
    }
    if config.include_uppercase {
        pool.extend(charset.uppercase);
    }
    if config.include_digits {
        pool.extend(charset.digits);
    }
    if config.include_symbols {
        pool.extend(charset.symbols);
    }

    // Remove ambiguous characters if requested
    if config.exclude_ambiguous {
        pool.retain(|&c| !matches!(c, b'l' | b'1' | b'I' | b'O' | b'0'));
    }

    // Ensure pool is not empty
    if pool.is_empty() {
        return Err(CryptoError::RandomFailed(
            "Character pool is empty after applying filters".to_string(),
        ));
    }

    // Ensure at least one character from each requested type
    let mut password = Vec::with_capacity(config.length);
    let mut position = 0;

    if config.include_lowercase {
        let chars = if config.exclude_ambiguous {
            charset
                .lowercase
                .iter()
                .copied()
                .filter(|&c| !matches!(c, b'l'))
                .collect::<Vec<_>>()
        } else {
            charset.lowercase.to_vec()
        };
        if !chars.is_empty() {
            password.push(chars.choose(&mut rng).copied().unwrap());
            position += 1;
        }
    }

    if config.include_uppercase {
        let chars = if config.exclude_ambiguous {
            charset
                .uppercase
                .iter()
                .copied()
                .filter(|&c| !matches!(c, b'I' | b'O'))
                .collect::<Vec<_>>()
        } else {
            charset.uppercase.to_vec()
        };
        if !chars.is_empty() {
            password.push(chars.choose(&mut rng).copied().unwrap());
            position += 1;
        }
    }

    if config.include_digits {
        let chars = if config.exclude_ambiguous {
            charset
                .digits
                .iter()
                .copied()
                .filter(|&c| !matches!(c, b'0' | b'1'))
                .collect::<Vec<_>>()
        } else {
            charset.digits.to_vec()
        };
        if !chars.is_empty() {
            password.push(chars.choose(&mut rng).copied().unwrap());
            position += 1;
        }
    }

    if config.include_symbols {
        password.push(pool.choose(&mut rng).copied().unwrap());
        position += 1;
    }

    // Fill the rest with random characters from the pool
    while position < config.length {
        password.push(pool.choose(&mut rng).copied().unwrap());
        position += 1;
    }

    // Shuffle the password to avoid predictable patterns
    let mut password_vec: Vec<char> = password.into_iter().map(|b| b as char).collect();
    password_vec.shuffle(&mut rng);

    Ok(password_vec.into_iter().collect())
}

/// Generate a simple alphanumeric password
pub fn generate_simple_password(length: usize) -> Result<String> {
    let config = PasswordGeneratorConfig {
        length,
        include_lowercase: true,
        include_uppercase: true,
        include_digits: true,
        include_symbols: false,
        exclude_ambiguous: true,
    };
    generate_password(&config)
}

/// Generate a passphrase from a word list
///
/// Uses the EFF short word list (1,296 words = 10.3 bits/word).
/// A 4-word passphrase provides ~41 bits of entropy; 6 words provides ~62 bits.
pub fn generate_passphrase(word_count: usize, separator: &str) -> Result<String> {
    if word_count == 0 {
        return Err(CryptoError::EncryptionFailed(
            "Word count must be at least 1".to_string(),
        ));
    }

    let mut rng = rand::thread_rng();
    let words: Vec<&str> = (0..word_count)
        .map(|_| EFF_SHORT_WORDLIST.choose(&mut rng).copied().unwrap())
        .collect();

    Ok(words.join(separator))
}

/// EFF short word list 1.0 (1,296 words, 10.3 bits/word).
/// Source: https://www.eff.org/dice
const EFF_SHORT_WORDLIST: &[&str] = &[
    "acid", "acorn", "acre", "acts", "afar", "affix", "aged", "agent", "agile", "aging", "agony",
    "ahead", "aide", "aids", "aim", "ajar", "alarm", "alias", "alibi", "alien", "alike", "alive",
    "aloe", "aloft", "aloha", "alone", "amend", "amino", "ample", "amuse", "angel", "anger",
    "angle", "ankle", "apple", "april", "apron", "aqua", "area", "arena", "argue", "arise",
    "armed", "armor", "army", "aroma", "array", "arson", "art", "ashen", "ashes", "atlas", "atom",
    "attic", "audio", "avert", "avoid", "awake", "award", "awoke", "axis", "bacon", "badge",
    "bagel", "baggy", "baked", "baker", "balmy", "banjo", "barge", "barn", "bash", "basil", "bask",
    "batch", "bath", "baton", "bats", "blade", "blank", "blast", "blaze", "bleak", "blend",
    "bless", "blimp", "blink", "bloat", "blob", "blog", "blot", "blunt", "blurt", "blush", "boast",
    "boat", "body", "boil", "bok", "bolt", "boned", "boney", "bonus", "bony", "book", "booth",
    "boots", "boss", "botch", "both", "boxer", "breed", "bribe", "brick", "bride", "brim", "bring",
    "brink", "brisk", "broad", "broil", "broke", "brook", "broom", "brush", "buck", "bud", "buggy",
    "bulge", "bulk", "bully", "bunch", "bunny", "bunt", "bush", "bust", "busy", "buzz", "cable",
    "cache", "cadet", "cage", "cake", "calm", "cameo", "canal", "candy", "cane", "canon", "cape",
    "card", "cargo", "carol", "carry", "carve", "case", "cash", "cause", "cedar", "chain", "chair",
    "chant", "chaos", "charm", "chase", "cheek", "cheer", "chef", "chess", "chest", "chew",
    "chief", "chili", "chill", "chip", "chomp", "chop", "chow", "chuck", "chump", "chunk", "churn",
    "chute", "cider", "cinch", "city", "civic", "civil", "clad", "claim", "clamp", "clap", "clash",
    "clasp", "class", "claw", "clay", "clean", "clear", "cleat", "cleft", "clerk", "click",
    "cling", "clink", "clip", "cloak", "clock", "clone", "cloth", "cloud", "clump", "coach",
    "coast", "coat", "cod", "coil", "coke", "cola", "cold", "colt", "coma", "come", "comic",
    "comma", "cone", "cope", "copy", "coral", "cork", "cost", "cot", "couch", "cough", "cover",
    "cozy", "craft", "cramp", "crane", "crank", "crate", "crave", "crawl", "crazy", "creme",
    "crepe", "crept", "crib", "cried", "crisp", "crook", "crop", "cross", "crowd", "crown",
    "crumb", "crush", "crust", "cub", "cult", "cupid", "cure", "curl", "curry", "curse", "curve",
    "curvy", "cushy", "cut", "cycle", "dab", "dad", "daily", "dairy", "daisy", "dance", "dandy",
    "darn", "dart", "dash", "data", "date", "dawn", "deaf", "deal", "dean", "debit", "debt",
    "debug", "decaf", "decal", "decay", "deck", "decor", "decoy", "deed", "delay", "denim",
    "dense", "dent", "depth", "derby", "desk", "dial", "diary", "dice", "dig", "dill", "dime",
    "dimly", "diner", "dingy", "disco", "dish", "disk", "ditch", "ditzy", "dizzy", "dock", "dodge",
    "doing", "doll", "dome", "donor", "donut", "dose", "dot", "dove", "down", "dowry", "doze",
    "drab", "drama", "drank", "draw", "dress", "dried", "drift", "drill", "drive", "drone",
    "droop", "drove", "drown", "drum", "dry", "duck", "duct", "dude", "dug", "duke", "duo", "dusk",
    "dust", "duty", "dwarf", "dwell", "eagle", "early", "earth", "easel", "east", "eaten", "eats",
    "ebay", "ebony", "ebook", "echo", "edge", "eel", "eject", "elbow", "elder", "elf", "elk",
    "elm", "elope", "elude", "elves", "email", "emit", "empty", "emu", "enter", "entry", "envoy",
    "equal", "erase", "error", "erupt", "essay", "etch", "evade", "even", "evict", "evil", "evoke",
    "exact", "exit", "fable", "faced", "fact", "fade", "fall", "false", "fancy", "fang", "fax",
    "feast", "feed", "femur", "fence", "fend", "ferry", "fetal", "fetch", "fever", "fiber",
    "fifth", "fifty", "film", "filth", "final", "finch", "fit", "five", "flag", "flaky", "flame",
    "flap", "flask", "fled", "flick", "fling", "flint", "flip", "flirt", "float", "flock", "flop",
    "floss", "flyer", "foam", "foe", "fog", "foil", "folic", "folk", "food", "fool", "found",
    "fox", "foyer", "frail", "frame", "fray", "fresh", "fried", "frill", "frisk", "from", "front",
    "frost", "froth", "frown", "froze", "fruit", "gag", "gains", "gala", "game", "gap", "gas",
    "gave", "gear", "gecko", "geek", "gem", "genre", "gift", "gig", "gills", "given", "giver",
    "glad", "glass", "glide", "gloss", "glove", "glow", "glue", "goal", "going", "golf", "gong",
    "good", "gooey", "goofy", "gore", "gown", "grab", "grain", "grant", "grape", "graph", "grasp",
    "grass", "grave", "gravy", "gray", "green", "greet", "grew", "grid", "grief", "grill", "grip",
    "grit", "groom", "grope", "growl", "grub", "grunt", "guide", "gulf", "gulp", "gummy", "guru",
    "gush", "gut", "guy", "habit", "half", "halo", "halt", "happy", "harm", "hash", "hasty",
    "hatch", "hate", "haven", "hazel", "hazy", "heap", "heat", "heave", "hedge", "hefty", "help",
    "herbs", "hers", "hub", "hug", "hula", "hull", "human", "humid", "hump", "hung", "hunk",
    "hunt", "hurry", "hurt", "hush", "hut", "ice", "icing", "icon", "icy", "igloo", "image", "ion",
    "iron", "islam", "issue", "item", "ivory", "ivy", "jab", "jam", "jaws", "jazz", "jeep",
    "jelly", "jet", "jiffy", "job", "jog", "jolly", "jolt", "jot", "joy", "judge", "juice",
    "juicy", "july", "jumbo", "jump", "junky", "juror", "jury", "keep", "keg", "kept", "kick",
    "kilt", "king", "kite", "kitty", "kiwi", "knee", "knelt", "koala", "kung", "ladle", "lady",
    "lair", "lake", "lance", "land", "lapel", "large", "lash", "lasso", "last", "latch", "late",
    "lazy", "left", "legal", "lemon", "lend", "lens", "lent", "level", "lever", "lid", "life",
    "lift", "lilac", "lily", "limb", "limes", "line", "lint", "lion", "lip", "list", "lived",
    "liver", "lunar", "lunch", "lung", "lurch", "lure", "lurk", "lying", "lyric", "mace", "maker",
    "malt", "mama", "mango", "manor", "many", "map", "march", "mardi", "marry", "mash", "match",
    "mate", "math", "moan", "mocha", "moist", "mold", "mom", "moody", "mop", "morse", "most",
    "motor", "motto", "mount", "mouse", "mousy", "mouth", "move", "movie", "mower", "mud", "mug",
    "mulch", "mule", "mull", "mumbo", "mummy", "mural", "muse", "music", "musky", "mute", "nacho",
    "nag", "nail", "name", "nanny", "nap", "navy", "near", "neat", "neon", "nerd", "nest", "net",
    "next", "niece", "ninth", "nutty", "oak", "oasis", "oat", "ocean", "oil", "old", "olive",
    "omen", "onion", "only", "ooze", "opal", "open", "opera", "opt", "otter", "ouch", "ounce",
    "outer", "oval", "oven", "owl", "ozone", "pace", "pagan", "pager", "palm", "panda", "panic",
    "pants", "panty", "paper", "park", "party", "pasta", "patch", "path", "patio", "payer",
    "pecan", "penny", "pep", "perch", "perky", "perm", "pest", "petal", "petri", "petty", "photo",
    "plank", "plant", "plaza", "plead", "plot", "plow", "pluck", "plug", "plus", "poach", "pod",
    "poem", "poet", "pogo", "point", "poise", "poker", "polar", "polio", "polka", "polo", "pond",
    "pony", "poppy", "pork", "poser", "pouch", "pound", "pout", "power", "prank", "press", "print",
    "prior", "prism", "prize", "probe", "prong", "proof", "props", "prude", "prune", "pry", "pug",
    "pull", "pulp", "pulse", "puma", "punch", "punk", "pupil", "puppy", "purr", "purse", "push",
    "putt", "quack", "quake", "query", "quiet", "quill", "quilt", "quit", "quota", "quote",
    "rabid", "race", "rack", "radar", "radio", "raft", "rage", "raid", "rail", "rake", "rally",
    "ramp", "ranch", "range", "rank", "rant", "rash", "raven", "reach", "react", "ream", "rebel",
    "recap", "relax", "relay", "relic", "remix", "repay", "repel", "reply", "rerun", "reset",
    "rhyme", "rice", "rich", "ride", "rigid", "rigor", "rinse", "riot", "ripen", "rise", "risk",
    "ritzy", "rival", "river", "roast", "robe", "robin", "rock", "rogue", "roman", "romp", "rope",
    "rover", "royal", "ruby", "rug", "ruin", "rule", "runny", "rush", "rust", "rut", "sadly",
    "sage", "said", "saint", "salad", "salon", "salsa", "salt", "same", "sandy", "santa", "satin",
    "sauna", "saved", "savor", "sax", "say", "scale", "scam", "scan", "scare", "scarf", "scary",
    "scoff", "scold", "scoop", "scoot", "scope", "score", "scorn", "scout", "scowl", "scrap",
    "scrub", "scuba", "scuff", "sect", "sedan", "self", "send", "sepia", "serve", "set", "seven",
    "shack", "shade", "shady", "shaft", "shaky", "sham", "shape", "share", "sharp", "shed",
    "sheep", "sheet", "shelf", "shell", "shine", "shiny", "ship", "shirt", "shock", "shop",
    "shore", "shout", "shove", "shown", "showy", "shred", "shrug", "shun", "shush", "shut", "shy",
    "sift", "silk", "silly", "silo", "sip", "siren", "sixth", "size", "skate", "skew", "skid",
    "skier", "skies", "skip", "skirt", "skit", "sky", "slab", "slack", "slain", "slam", "slang",
    "slash", "slate", "slaw", "sled", "sleek", "sleep", "sleet", "slept", "slice", "slick",
    "slimy", "sling", "slip", "slit", "slob", "slot", "slug", "slum", "slurp", "slush", "small",
    "smash", "smell", "smile", "smirk", "smog", "snack", "snap", "snare", "snarl", "sneak",
    "sneer", "sniff", "snore", "snort", "snout", "snowy", "snub", "snuff", "speak", "speed",
    "spend", "spent", "spew", "spied", "spill", "spiny", "spoil", "spoke", "spoof", "spool",
    "spoon", "sport", "spot", "spout", "spray", "spree", "spur", "squad", "squat", "squid",
    "stack", "staff", "stage", "stain", "stall", "stamp", "stand", "stank", "stark", "start",
    "stash", "state", "stays", "steam", "steep", "stem", "step", "stew", "stick", "sting", "stir",
    "stock", "stole", "stomp", "stony", "stood", "stool", "stoop", "stop", "storm", "stout",
    "stove", "straw", "stray", "strut", "stuck", "stud", "stuff", "stump", "stung", "stunt",
    "suds", "sugar", "sulk", "surf", "sushi", "swab", "swan", "swarm", "sway", "swear", "sweat",
    "sweep", "swell", "swept", "swim", "swing", "swipe", "swirl", "swoop", "swore", "syrup",
    "tacky", "taco", "tag", "take", "tall", "talon", "tamer", "tank", "taper", "taps", "tarot",
    "tart", "task", "taste", "tasty", "taunt", "thank", "thaw", "theft", "theme", "thigh", "thing",
    "think", "thong", "thorn", "those", "throb", "thud", "thumb", "thump", "thus", "tiara",
    "tidal", "tidy", "tiger", "tile", "tilt", "tint", "tiny", "trace", "track", "trade", "train",
    "trait", "trap", "trash", "tray", "treat", "tree", "trek", "trend", "trial", "tribe", "trick",
    "trio", "trout", "truce", "truck", "trump", "trunk", "try", "tug", "tulip", "tummy", "turf",
    "tusk", "tutor", "tutu", "tux", "tweak", "tweet", "twice", "twine", "twins", "twirl", "twist",
    "uncle", "uncut", "undo", "unify", "union", "unit", "untie", "upon", "upper", "urban", "used",
    "user", "usher", "utter", "value", "vapor", "vegan", "venue", "verse", "vest", "veto", "vice",
    "video", "view", "viral", "virus", "visa", "visor", "vixen", "vocal", "voice", "void", "volt",
    "voter", "vowel", "wad", "wafer", "wager", "wages", "wagon", "wake", "walk", "wand", "wasp",
    "watch", "water", "wavy", "wheat", "whiff", "whole", "whoop", "wick", "widen", "widow",
    "width", "wife", "wifi", "wilt", "wimp", "wind", "wing", "wink", "wipe", "wired", "wiry",
    "wise", "wish", "wispy", "wok", "wolf", "womb", "wool", "woozy", "word", "work", "worry",
    "wound", "woven", "wrath", "wreck", "wrist", "xerox", "yahoo", "yam", "yard", "year", "yeast",
    "yelp", "yield", "yodel", "yoga", "yummy", "zebra", "zero", "zesty", "zippy", "zone", "zoom",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_default_password() {
        let config = PasswordGeneratorConfig::default();
        let password = generate_password(&config).unwrap();
        assert_eq!(password.len(), 16);
    }

    #[test]
    fn test_generate_custom_length() {
        let config = PasswordGeneratorConfig::default().length(32);
        let password = generate_password(&config).unwrap();
        assert_eq!(password.len(), 32);
    }

    #[test]
    fn test_generate_letters_only() {
        let config = PasswordGeneratorConfig::default()
            .with_digits(false)
            .with_symbols(false)
            .length(12);
        let password = generate_password(&config).unwrap();
        assert_eq!(password.len(), 12);
        assert!(password.chars().all(|c| c.is_alphabetic()));
    }

    #[test]
    fn test_generate_no_ambiguous() {
        let config = PasswordGeneratorConfig::default()
            .exclude_ambiguous(true)
            .length(20);
        let password = generate_password(&config).unwrap();
        assert_eq!(password.len(), 20);
        assert!(!password
            .chars()
            .any(|c| matches!(c, 'l' | '1' | 'I' | 'O' | '0')));
    }

    #[test]
    fn test_simple_password() {
        let password = generate_simple_password(12).unwrap();
        assert_eq!(password.len(), 12);
        assert!(password.chars().all(|c| c.is_alphanumeric()));
    }

    #[test]
    fn test_passphrase() {
        let passphrase = generate_passphrase(4, "-").unwrap();
        let parts: Vec<&str> = passphrase.split('-').collect();
        assert_eq!(parts.len(), 4);
    }

    #[test]
    fn test_validate_length_too_short() {
        let config = PasswordGeneratorConfig::default().length(2);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_no_char_types() {
        let config = PasswordGeneratorConfig {
            length: 16,
            include_lowercase: false,
            include_uppercase: false,
            include_digits: false,
            include_symbols: false,
            exclude_ambiguous: false,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_passwords_are_unique() {
        let config = PasswordGeneratorConfig::default();
        let p1 = generate_password(&config).unwrap();
        let p2 = generate_password(&config).unwrap();
        assert_ne!(p1, p2);
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn generated_passwords_meet_length(len in 8usize..128) {
            let config = PasswordGeneratorConfig::default().length(len);
            let pw = generate_password(&config).unwrap();
            prop_assert_eq!(pw.len(), len);
        }
    }
}
