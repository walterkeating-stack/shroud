/**
 * Fake name generators for persons, organizations, and locations.
 *
 * Includes semantic/cultural matching -- CJK names get CJK fakes,
 * Hispanic names get Hispanic fakes, etc.
 */

import { Category } from "../types.js";
import type { BaseGenerator } from "./base.js";

// --- Cultural name pools ---

// CJK names (Chinese/Japanese/Korean)
export const CJK_FIRST = [
  "Haruki", "Yuki", "Ren", "Sora", "Hana", "Mei", "Kai", "Ryo",
  "Aoi", "Sakura", "Wei", "Min", "Jun", "Lin", "Jing", "Xiao",
  "Soo", "Jin", "Hyun", "Yeon", "Tae", "Haru", "Nao", "Shin",
];
export const CJK_LAST = [
  "Tanaka", "Suzuki", "Takahashi", "Watanabe", "Yamamoto", "Nakamura",
  "Chen", "Wang", "Li", "Zhang", "Liu", "Yang",
  "Kim", "Park", "Lee", "Choi", "Jung", "Kang",
  "Sato", "Ito", "Kobayashi", "Mori", "Hayashi", "Ono",
];

// Hispanic/Latin names
export const HISPANIC_FIRST = [
  "Carlos", "Maria", "Diego", "Sofia", "Lucas", "Valentina", "Mateo", "Camila",
  "Santiago", "Isabella", "Miguel", "Lucia", "Andres", "Elena", "Pablo", "Ana",
  "Rafael", "Carmen", "Gabriel", "Rosa", "Fernando", "Luisa", "Javier", "Pilar",
];
export const HISPANIC_LAST = [
  "Garcia", "Rodriguez", "Martinez", "Lopez", "Hernandez", "Gonzalez",
  "Perez", "Sanchez", "Ramirez", "Torres", "Flores", "Rivera",
  "Diaz", "Morales", "Ortiz", "Reyes", "Cruz", "Castillo",
  "Mendoza", "Vargas", "Romero", "Ruiz", "Alvarez", "Jimenez",
];

// Arabic/Middle Eastern names
export const ARABIC_FIRST = [
  "Omar", "Fatima", "Hassan", "Layla", "Youssef", "Amira", "Khalid", "Nour",
  "Tariq", "Salma", "Rashid", "Zahra", "Karim", "Leila", "Samir", "Hana",
  "Faris", "Dina", "Nabil", "Rania", "Amir", "Yasmin", "Zaid", "Muna",
];
export const ARABIC_LAST = [
  "Al-Rashid", "Hassan", "Ibrahim", "Abbas", "Khalil", "Mahmoud",
  "Nasser", "Rahman", "Salem", "Haddad", "Bishara", "Farouk",
  "Mansour", "Qasim", "Sharif", "Taleb", "Wahab", "Zayed",
];

// South Asian names
export const SOUTH_ASIAN_FIRST = [
  "Arjun", "Priya", "Raj", "Ananya", "Vikram", "Sita", "Rohan", "Meera",
  "Arun", "Kavita", "Sanjay", "Nisha", "Amit", "Pooja", "Sunil", "Rekha",
  "Harsh", "Deepa", "Nikhil", "Asha", "Ravi", "Lata", "Kiran", "Maya",
];
export const SOUTH_ASIAN_LAST = [
  "Patel", "Sharma", "Singh", "Kumar", "Gupta", "Mehta",
  "Reddy", "Nair", "Rao", "Verma", "Joshi", "Shah",
  "Das", "Mishra", "Srinivasan", "Krishnamurthy", "Pillai", "Iyer",
];

export const FIRST_NAMES = [
  "Alex", "Blake", "Casey", "Dana", "Ellis", "Frankie", "Gray", "Harper",
  "Indigo", "Jordan", "Kai", "Lane", "Morgan", "Noah", "Oakley", "Parker",
  "Quinn", "Reese", "Sage", "Taylor", "Uma", "Val", "Wren", "Xen",
  "Yael", "Zara", "Avery", "Brook", "Cedar", "Drew", "Eden", "Fern",
  "Glen", "Haven", "Iris", "Jules", "Kira", "Lark", "Marlo", "Nico",
  "Onyx", "Phoenix", "Rain", "Skyler", "Tatum", "Unity", "Vesper", "Winter",
];

export const LAST_NAMES = [
  "Stone", "Rivers", "Bell", "Cross", "Drake", "Fields", "Grant", "Hayes",
  "Ivy", "James", "Knight", "Lake", "Moon", "North", "Oak", "Price",
  "Reed", "Shaw", "Thorn", "Vale", "Ward", "York", "Ash", "Banks",
  "Cole", "Dawn", "East", "Frost", "Gold", "Hill", "Jade", "King",
  "Lowe", "Marsh", "Noel", "Peak", "Rose", "Snow", "Troy", "Vane",
  "Wells", "Birch", "Clay", "Dove", "Elm", "Fox", "Gale", "Hart",
];

export const ORG_PREFIXES = [
  "Nexus", "Vertex", "Prism", "Atlas", "Cipher", "Beacon", "Forge", "Crest",
  "Pulse", "Apex", "Echo", "Nova", "Summit", "Core", "Bridge", "Spark",
  "Tide", "Haven", "Peak", "Drift", "Flux", "Orbit", "Zenith", "Pine",
];

export const ORG_SUFFIXES = [
  "Corp", "Labs", "Systems", "Group", "Inc", "Partners", "Technologies",
  "Industries", "Networks", "Solutions", "Dynamics", "Ventures", "Digital",
  "Analytics", "Collective", "Innovations", "Software", "Consulting",
  "Strategies", "Media", "Engineering", "Capital", "Works", "Services",
];

export const LOCATIONS = [
  "Maple Ridge", "Cedar Falls", "Pine Valley", "Oak Harbor", "Birch Creek",
  "Silver Lake", "Crystal Bay", "Shadow Glen", "Amber Hills", "Coral Springs",
  "Iron Bridge", "Stone Haven", "River Bend", "Summit View", "Harbor Point",
  "Eagle Pass", "Fox Hollow", "Raven Cliff", "Wolf Creek", "Bear Valley",
  "Falcon Heights", "Elk Grove", "Lark Meadow", "Heron Bay", "Sparrow Hill",
  "Aspen Ridge", "Willow Park", "Jasper Cove", "Slate Crossing", "Flint Mesa",
];

// --- Cultural detection helpers ---

const CJK_RE = /[\u4E00-\u9FFF\u3040-\u309F\u30A0-\u30FF\uAC00-\uD7AF]/;

const HISPANIC_PATTERNS = new RegExp(
  "(?:Garcia|Rodriguez|Martinez|Lopez|Hernandez|Gonzalez|Perez|Sanchez|" +
  "Ramirez|Torres|Flores|Rivera|Diaz|Morales|Cruz|Reyes|Castillo|" +
  "Juan|Jose|Maria|Carlos|Miguel|Diego|Sofia|Camila|Santiago)",
  "i",
);

const ARABIC_PATTERNS = new RegExp(
  "(?:Al-|Abu |Ibn |Mohammed|Muhammad|Ahmed|Hassan|Hussein|Fatima|Omar|" +
  "Khalid|Youssef|Tariq|Rashid|Karim|Nour|Zahra|Layla)",
  "i",
);

const SOUTH_ASIAN_PATTERNS = new RegExp(
  "(?:Kumar|Singh|Patel|Sharma|Gupta|Mehta|Reddy|Nair|Rao|" +
  "Srinivasan|Krishnamurthy|Arjun|Priya|Raj|Vikram|Sanjay|Amit)",
  "i",
);

/** Detect the likely cultural origin of a name. */
export function detectCulture(name: string): string {
  if (CJK_RE.test(name)) return "cjk";
  if (ARABIC_PATTERNS.test(name)) return "arabic";
  if (HISPANIC_PATTERNS.test(name)) return "hispanic";
  if (SOUTH_ASIAN_PATTERNS.test(name)) return "south_asian";
  return "western";
}

const CULTURE_POOLS: Record<string, [string[], string[]]> = {
  cjk: [CJK_FIRST, CJK_LAST],
  hispanic: [HISPANIC_FIRST, HISPANIC_LAST],
  arabic: [ARABIC_FIRST, ARABIC_LAST],
  south_asian: [SOUTH_ASIAN_FIRST, SOUTH_ASIAN_LAST],
  western: [FIRST_NAMES, LAST_NAMES],
};

function selectNamePools(
  original: string,
  _seed: number,
): [string[], string[]] {
  if (!original) return [FIRST_NAMES, LAST_NAMES];
  const culture = detectCulture(original);
  return CULTURE_POOLS[culture] ?? [FIRST_NAMES, LAST_NAMES];
}

export class NameGenerator implements BaseGenerator {
  readonly categories = [
    Category.PERSON_NAME,
    Category.ORG_NAME,
    Category.LOCATION,
  ];

  generate(category: Category, seed: number, original = ""): string {
    if (category === Category.PERSON_NAME) {
      return this._fakePerson(seed, original);
    } else if (category === Category.ORG_NAME) {
      return this._fakeOrg(seed, original);
    } else if (category === Category.LOCATION) {
      return LOCATIONS[seed % LOCATIONS.length];
    }
    return `Entity-${String(seed % 10000).padStart(4, "0")}`;
  }

  private _fakePerson(seed: number, original: string): string {
    const [firstPool, lastPool] = selectNamePools(original, seed);
    const first = firstPool[seed % firstPool.length];
    const last = lastPool[Math.floor(seed / firstPool.length) % lastPool.length];

    if (!original) return `${first} ${last}`;

    // Preserve the structure of the original name
    const parts = original.split(" ");
    if (parts.length === 1) {
      return first;
    } else if (parts.length === 3) {
      const middle = firstPool[Math.floor(seed / 3) % firstPool.length];
      return `${first} ${middle} ${last}`;
    } else if (parts.length > 3) {
      const extra: string[] = [];
      for (let i = 0; i < parts.length - 2; i++) {
        extra.push(firstPool[(seed + i) % firstPool.length]);
      }
      return [first, ...extra, last].join(" ");
    }

    // Preserve separator (hyphen, period)
    if (original.includes("-") && !original.includes(" ")) {
      return `${first}-${last}`;
    }
    if (original.includes(".") && !original.includes(" ")) {
      return `${first[0]}.${last}`;
    }

    return `${first} ${last}`;
  }

  private _fakeOrg(seed: number, original: string): string {
    const prefix = ORG_PREFIXES[seed % ORG_PREFIXES.length];
    const suffix =
      ORG_SUFFIXES[
        Math.floor(seed / ORG_PREFIXES.length) % ORG_SUFFIXES.length
      ];

    if (!original) return `${prefix} ${suffix}`;

    // Match word count of original
    const origWords = original.split(" ");
    if (origWords.length === 1) {
      return prefix;
    } else if (origWords.length === 2) {
      return `${prefix} ${suffix}`;
    } else {
      const extras: string[] = [];
      for (let i = 1; i < origWords.length - 1; i++) {
        extras.push(ORG_PREFIXES[(seed + i) % ORG_PREFIXES.length]);
      }
      return [prefix, ...extras, suffix].join(" ");
    }
  }
}
