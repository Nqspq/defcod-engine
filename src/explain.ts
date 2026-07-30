// Объяснения находок простым языком.
// Заготовленные тексты (EN/RU) для каждого типа находки — движок полностью
// автономен и не требует никаких внешних API. Улучшение текстов через LLM
// (если нужно) — забота приложения поверх движка, не самого движка.

import type { Finding, FindingType } from "./rules";

// Языки заготовленных объяснений.
export type Lang = "en" | "ru";

export type FindingTexts = { title: string; explanation: string; fix: string[] };

// Тексты находки сразу на ОБОИХ языках — какой показать, решает клиент.
export type ExplainedFinding = Finding & {
  texts: Record<Lang, FindingTexts>;
};

type Texts = FindingTexts;

// Заготовленные объяснения для каждого типа находки.
const CANNED: Record<FindingType, Record<Lang, Texts>> = {
  openai_key: {
    en: {
      title: "OpenAI API key in your code",
      explanation:
        "This key is like a bank card linked to your OpenAI account. Anyone who sees your code can copy it and spend your money on their own requests.",
      fix: [
        "Go to platform.openai.com → API keys and revoke this key.",
        "Create a new key and put it in an environment variable (a .env file that is NOT in the repository).",
        "In code, read it as process.env.OPENAI_API_KEY instead of pasting the key itself.",
      ],
    },
    ru: {
      title: "Ключ OpenAI прямо в коде",
      explanation:
        "Этот ключ — как банковская карта, привязанная к твоему аккаунту OpenAI. Любой, кто увидит код, может скопировать его и тратить твои деньги на свои запросы.",
      fix: [
        "Зайди на platform.openai.com → API keys и отзови этот ключ.",
        "Создай новый и положи его в переменную окружения (файл .env, которого НЕТ в репозитории).",
        "В коде читай его как process.env.OPENAI_API_KEY, а не вставляй сам ключ.",
      ],
    },
  },
  anthropic_key: {
    en: {
      title: "Anthropic (Claude) API key in your code",
      explanation:
        "Anyone who sees this key can make requests to Claude at your expense. Your bill can grow very fast.",
      fix: [
        "Go to console.anthropic.com → API keys and revoke this key.",
        "Create a new key and store it in an environment variable, never in code.",
      ],
    },
    ru: {
      title: "Ключ Anthropic (Claude) прямо в коде",
      explanation:
        "Любой, кто увидит этот ключ, сможет делать запросы к Claude за твой счёт. Счёт может вырасти очень быстро.",
      fix: [
        "Зайди в console.anthropic.com → API keys и отзови этот ключ.",
        "Создай новый и храни его в переменной окружения, а не в коде.",
      ],
    },
  },
  stripe_live_key: {
    en: {
      title: "Live Stripe secret key in your code",
      explanation:
        "This is the key to real money. With it, someone can see your customers' data and create refunds or payouts. This is one of the most dangerous leaks possible.",
      fix: [
        "Go to dashboard.stripe.com → Developers → API keys and roll (replace) this key immediately.",
        "Put the new key in an environment variable on the server only.",
        "Check the Stripe dashboard for suspicious activity.",
      ],
    },
    ru: {
      title: "Живой секретный ключ Stripe в коде",
      explanation:
        "Это ключ от настоящих денег. С ним можно увидеть данные твоих покупателей, делать возвраты и выплаты. Одна из самых опасных утечек вообще.",
      fix: [
        "Зайди в dashboard.stripe.com → Developers → API keys и немедленно замени (roll) этот ключ.",
        "Новый ключ положи в переменную окружения только на сервере.",
        "Проверь в панели Stripe, не было ли подозрительных операций.",
      ],
    },
  },
  aws_key: {
    en: {
      title: "AWS access key in your code",
      explanation:
        "With this key, a stranger can use Amazon's cloud on your behalf: spin up expensive servers for crypto mining or read your files. Bills can reach thousands of dollars in hours.",
      fix: [
        "Go to AWS Console → IAM → Security credentials and deactivate this key right now.",
        "Create a new key, store it in environment variables, and never commit it.",
        "Check AWS Billing for unexpected charges.",
      ],
    },
    ru: {
      title: "Ключ доступа AWS в коде",
      explanation:
        "С этим ключом чужой человек может пользоваться облаком Amazon от твоего имени: поднять дорогие серверы для майнинга или читать твои файлы. Счета могут вырасти до тысяч долларов за часы.",
      fix: [
        "Зайди в AWS Console → IAM → Security credentials и немедленно отключи этот ключ.",
        "Создай новый, храни его в переменных окружения и никогда не коммить.",
        "Проверь раздел Billing в AWS — нет ли неожиданных трат.",
      ],
    },
  },
  google_key: {
    en: {
      title: "Google API key in your code",
      explanation:
        "Someone can use your Google services (Maps, Firebase, etc.) at your expense, or reach data behind this key.",
      fix: [
        "Go to console.cloud.google.com → APIs & Services → Credentials and delete or restrict this key.",
        "Create a new key with restrictions (allowed sites/apps only) and keep it in environment variables.",
      ],
    },
    ru: {
      title: "Ключ Google API в коде",
      explanation:
        "Кто-то может пользоваться твоими сервисами Google (Maps, Firebase и др.) за твой счёт или добраться до данных, которые за этим ключом стоят.",
      fix: [
        "Зайди в console.cloud.google.com → APIs & Services → Credentials и удали или ограничь этот ключ.",
        "Создай новый ключ с ограничениями (только твои сайты/приложения) и храни его в переменных окружения.",
      ],
    },
  },
  supabase_service_role: {
    en: {
      title: "Supabase service_role key exposed",
      explanation:
        "The service_role key is the master key to your entire database. It ignores all security rules (RLS): with it, anyone can read, change or delete ALL data of ALL users. If it's in client code, every visitor of your site can extract it.",
      fix: [
        "Go to Supabase → Project Settings → API and reset (rotate) the service_role key.",
        "Never use service_role in a browser/client. In the browser, only the anon key is allowed.",
        "Keep service_role in server environment variables only (API routes, edge functions).",
      ],
    },
    ru: {
      title: "Supabase service_role ключ наружу",
      explanation:
        "Ключ service_role — это мастер-ключ от всей твоей базы данных. Он игнорирует все правила безопасности (RLS): с ним можно читать, менять и удалять ВСЕ данные ВСЕХ пользователей. Если он в клиентском коде — его может достать каждый посетитель сайта.",
      fix: [
        "Зайди в Supabase → Project Settings → API и перевыпусти (rotate) service_role ключ.",
        "Никогда не используй service_role в браузере/клиенте. В браузере допустим только anon ключ.",
        "Храни service_role только в переменных окружения на сервере (API-роуты, edge-функции).",
      ],
    },
  },
  private_key: {
    en: {
      title: "Private key file in the repository",
      explanation:
        "A private key is like the physical key to your server or account. Whoever has the file can impersonate you: connect to your servers or sign things in your name.",
      fix: [
        "Remove the key from the repository and consider it compromised.",
        "Generate a new key pair and replace the old one everywhere it was used.",
        "Add key files (*.pem, id_rsa, etc.) to .gitignore.",
      ],
    },
    ru: {
      title: "Файл приватного ключа в репозитории",
      explanation:
        "Приватный ключ — как физический ключ от твоего сервера или аккаунта. Тот, у кого есть файл, может выдавать себя за тебя: подключаться к серверам или подписывать что-то от твоего имени.",
      fix: [
        "Убери ключ из репозитория и считай его скомпрометированным.",
        "Сгенерируй новую пару ключей и замени старую везде, где она использовалась.",
        "Добавь файлы ключей (*.pem, id_rsa и т.п.) в .gitignore.",
      ],
    },
  },
  hardcoded_secret: {
    en: {
      title: "Password or secret written directly in code",
      explanation:
        "A password or token is written as plain text in the code. Anyone who sees the code learns the secret — and code gets shared, copied and leaked more often than you think.",
      fix: [
        "Move the value into an environment variable (a .env file outside the repository).",
        "Change the password/token itself — it may already be compromised.",
      ],
    },
    ru: {
      title: "Пароль или секрет прямо в коде",
      explanation:
        "Пароль или токен записан открытым текстом в коде. Любой, кто видит код, узнаёт секрет — а код показывают, копируют и сливают чаще, чем кажется.",
      fix: [
        "Вынеси значение в переменную окружения (файл .env вне репозитория).",
        "Поменяй сам пароль/токен — он уже мог утечь.",
      ],
    },
  },
  env_file: {
    en: {
      title: ".env file with real values committed",
      explanation:
        "The .env file is the box where all your secrets live. It ended up in the repository, so everyone who can see the code also sees every key and password inside it.",
      fix: [
        "Add .env (and .env.local, .env.production) to .gitignore.",
        "Remove the file from the repository history — simply deleting it is not enough, old versions keep it.",
        "Replace every key and password that was inside: they are all compromised now.",
      ],
    },
    ru: {
      title: "Файл .env с настоящими значениями в репозитории",
      explanation:
        "Файл .env — это коробка, где лежат все твои секреты. Она попала в репозиторий, и каждый, кто видит код, видит и все ключи с паролями внутри.",
      fix: [
        "Добавь .env (и .env.local, .env.production) в .gitignore.",
        "Убери файл из истории репозитория — просто удалить мало, старые версии его хранят.",
        "Замени все ключи и пароли, которые там лежали: они уже скомпрометированы.",
      ],
    },
  },
  google_key_public: {
    en: {
      title: "Google API key meant for the browser (restrict it)",
      explanation:
        "This key sits in a variable whose name says it is a browser key — a Google Maps key, for example, is sent to every visitor's page and cannot be kept secret. So this is not a leak. What matters is that such a key must be restricted, otherwise anyone can copy it from your page and run up your Google bill.",
      fix: [
        "Open console.cloud.google.com → APIs & Services → Credentials and pick this key.",
        "Under 'Application restrictions' allow only your own domains (HTTP referrers).",
        "Under 'API restrictions' allow only the APIs you actually use, and set a daily quota.",
      ],
    },
    ru: {
      title: "Ключ Google API для браузера (нужно ограничить)",
      explanation:
        "Этот ключ лежит в переменной, имя которой прямо говорит: он для браузера. Ключ Google Maps, например, уезжает на страницу каждому посетителю, и спрятать его невозможно. Так что это не утечка. Важно другое: такой ключ обязательно надо ограничить, иначе любой может скопировать его с твоей страницы и накрутить тебе счёт от Google.",
      fix: [
        "Зайди в console.cloud.google.com → APIs & Services → Credentials и выбери этот ключ.",
        "В «Application restrictions» разреши только свои домены (HTTP referrers).",
        "В «API restrictions» оставь только те API, которыми правда пользуешься, и поставь дневную квоту.",
      ],
    },
  },
  env_file_public: {
    en: {
      title: ".env file in the repository (public values only)",
      explanation:
        "Your .env file is in the repository, but everything inside it is meant to be public anyway — things like your Supabase project URL and the anon key, which every visitor's browser already receives. Nothing is leaking right now. It is still a habit worth fixing: the day you add a real secret to this file, it goes straight to the repository with it.",
      fix: [
        "Add .env (and .env.local, .env.production) to .gitignore now, before a real secret lands in it.",
        "Keep a .env.example in the repository instead: same variable names, no values.",
        "No need to rotate anything — these particular values were never secret.",
      ],
    },
    ru: {
      title: "Файл .env в репозитории (внутри только публичные значения)",
      explanation:
        "Файл .env лежит в репозитории, но всё, что внутри, и так публично по замыслу — адрес проекта Supabase и anon-ключ, которые браузер каждого посетителя получает и без этого. Прямо сейчас ничего не утекает. Привычку всё равно стоит поправить: в тот день, когда в этот файл добавят настоящий секрет, он уедет в репозиторий вместе с ним.",
      fix: [
        "Добавь .env (и .env.local, .env.production) в .gitignore прямо сейчас, пока в нём не появился настоящий секрет.",
        "Вместо него держи в репозитории .env.example: те же имена переменных, но без значений.",
        "Менять эти значения не нужно — они и не были секретными.",
      ],
    },
  },
};

// Дополнение для service_role в клиентском коде.
const CLIENT_CODE_NOTE: Record<Lang, string> = {
  en: " Found in CLIENT code — this is the worst case: the key is shipped to every visitor's browser.",
  ru: " Найден в КЛИЕНТСКОМ коде — это худший случай: ключ уезжает в браузер каждому посетителю.",
};

// Заготовленные тексты одной находки для одного языка.
function cannedFor(f: Finding, lang: Lang): FindingTexts {
  const t = CANNED[f.type][lang];
  const extra =
    f.type === "supabase_service_role" && f.inClientCode
      ? CLIENT_CODE_NOTE[lang]
      : "";
  return { title: t.title, explanation: t.explanation + extra, fix: t.fix };
}

// Заготовленные объяснения сразу на обоих языках.
export function cannedExplanations(findings: Finding[]): ExplainedFinding[] {
  return findings.map((f) => ({
    ...f,
    texts: { en: cannedFor(f, "en"), ru: cannedFor(f, "ru") },
  }));
}
