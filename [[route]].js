/* =========================================================
   IDX EBOOK AI
   PRODUCTION BACKEND
   PART 1 OF 4

   PLATFORM:
   Cloudflare Pages Functions

   SERVICES:
   DeepSeek
   Supabase
   Paymegate

   ========================================================= */

const APP_NAME = "IDX ebook AI";

const PDF_BUCKET = "idx-books";

const PAYMENT_PRICE = "5.00";

const PAYMENT_CURRENCY = "USD";

const DEEPSEEK_ENDPOINT =
    "https://api.deepseek.com/chat/completions";

const PAYMEGATE_ENDPOINT =
    "https://api.paymegate.com";

const encoder = new TextEncoder();

const decoder = new TextDecoder();

const JSON_HEADERS = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
};


/* =========================================================
   GENERAL HELPERS
   ========================================================= */

function json(data, status = 200, headers = {}) {

    return new Response(JSON.stringify(data), {
        status,
        headers: {
            ...JSON_HEADERS,
            ...headers
        }
    });

}


function fail(message, status = 400) {

    return json({
        success: false,
        error: message
    }, status);

}


function requiredEnv(env, name) {

    const value = env[name];

    if (!value) {
        throw new Error(
            "Missing Cloudflare environment secret: " + name
        );
    }

    return value;

}


function uuid() {

    return crypto.randomUUID();

}


function randomToken() {

    const bytes = crypto.getRandomValues(
        new Uint8Array(32)
    );

    return Array.from(bytes)
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");

}


async function sha256(value) {

    const digest = await crypto.subtle.digest(
        "SHA-256",
        encoder.encode(value)
    );

    return Array.from(new Uint8Array(digest))
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");

}


function safeText(value, max = 10000) {

    return String(value ?? "")
        .replace(/\u0000/g, "")
        .trim()
        .slice(0, max);

}


function escapeXML(value) {

    return String(value ?? "").replace(
        /[&<>"']/g,
        char => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&apos;"
        })[char]
    );

}


function validateEmail(email) {

    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}


/* =========================================================
   REQUEST SECURITY
   ========================================================= */

function verifyOrigin(request) {

    const origin = request.headers.get("Origin");

    if (!origin) return true;

    try {

        const requestOrigin = new URL(request.url).origin;

        return origin === requestOrigin;

    } catch {

        return false;

    }

}


async function readJSON(request, maxSize = 100000) {

    const text = await request.text();

    if (text.length > maxSize) {
        throw new Error("Request is too large.");
    }

    try {

        return JSON.parse(text);

    } catch {

        throw new Error("Invalid JSON request.");

    }

}


/* =========================================================
   PRIVATE ANONYMOUS USER SESSION

   The frontend sessionId is not trusted for authorization.

   Ownership is controlled by an HttpOnly cookie.
   ========================================================= */

function getCookie(request, name) {

    const cookie = request.headers.get("Cookie") || "";

    const parts = cookie.split(";");

    for (const part of parts) {

        const index = part.indexOf("=");

        if (index < 0) continue;

        const key = part.slice(0, index).trim();

        const value = part.slice(index + 1).trim();

        if (key === name) {
            return value;
        }

    }

    return null;

}


async function getSession(request, create = false) {

    const secure = new URL(request.url).protocol === "https:";

    const cookieName = secure
        ? "__Host-idx_session"
        : "idx_session";

    let token = getCookie(request, cookieName);

    let created = false;

    if (!token && create) {

        token = randomToken();

        created = true;

    }

    if (!token || !/^[a-f0-9]{64}$/.test(token)) {

        return null;

    }

    return {

        token,

        ownerHash: await sha256(token),

        cookieName,

        created

    };

}


function sessionCookie(session, request) {

    const secure =
        new URL(request.url).protocol === "https:";

    return [
        session.cookieName + "=" + session.token,
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=2592000",
        secure ? "Secure" : ""
    ].filter(Boolean).join("; ");

}


async function requireSession(request) {

    const session = await getSession(request, false);

    if (!session) {

        throw new Error(
            "Your session has expired. Start a new book."
        );

    }

    return session;

}


/* =========================================================
   SUPABASE REST CLIENT

   Uses the server-side service role key.

   Never expose this key in index.html.
   ========================================================= */

function supabaseBase(env) {

    return requiredEnv(env, "SUPABASE_URL")
        .replace(/\/+$/, "");

}


async function dbRequest(env, table, query = "", options = {}) {

    const base = supabaseBase(env);

    const key = requiredEnv(
        env,
        "SUPABASE_SERVICE_ROLE_KEY"
    );

    const url =
        base + "/rest/v1/" + table +
        (query ? "?" + query : "");

    const headers = {

        "apikey": key,

        "Authorization": "Bearer " + key,

        "Content-Type": "application/json",

        ...options.headers

    };

    const response = await fetch(url, {

        method: options.method || "GET",

        headers,

        body: options.body
            ? JSON.stringify(options.body)
            : undefined

    });

    const raw = await response.text();

    let result = null;

    try {

        result = raw ? JSON.parse(raw) : null;

    } catch {

        result = raw;

    }

    if (!response.ok) {

        console.error(
            "Supabase operation failed:",
            response.status,
            result
        );

        throw new Error(
            "Database operation failed."
        );

    }

    return result;

}


async function dbInsert(env, table, values) {

    return dbRequest(
        env,
        table,
        "",
        {
            method: "POST",

            headers: {
                "Prefer": "return=representation"
            },

            body: values
        }
    );

}


async function dbSelectOne(env, table, filters) {

    const params = new URLSearchParams();

    params.set("select", "*");

    params.set("limit", "1");

    for (const [key, value] of Object.entries(filters)) {

        params.set(key, "eq." + value);

    }

    const result = await dbRequest(
        env,
        table,
        params.toString()
    );

    return Array.isArray(result)
        ? result[0] || null
        : null;

}


async function dbUpdate(env, table, filters, values) {

    const params = new URLSearchParams();

    for (const [key, value] of Object.entries(filters)) {

        params.set(key, "eq." + value);

    }

    return dbRequest(
        env,
        table,
        params.toString(),
        {
            method: "PATCH",

            headers: {
                "Prefer": "return=representation"
            },

            body: values
        }
    );

}


/* =========================================================
   SUPABASE PRIVATE STORAGE
   ========================================================= */

async function uploadStorage(env, path, bytes, contentType) {

    const base = supabaseBase(env);

    const key = requiredEnv(
        env,
        "SUPABASE_SERVICE_ROLE_KEY"
    );

    const encodedPath = path
        .split("/")
        .map(encodeURIComponent)
        .join("/");

    const url =
        base +
        "/storage/v1/object/" +
        PDF_BUCKET +
        "/" +
        encodedPath;

    const response = await fetch(url, {

        method: "POST",

        headers: {

            "apikey": key,

            "Authorization": "Bearer " + key,

            "Content-Type": contentType,

            "x-upsert": "true"

        },

        body: bytes

    });

    if (!response.ok) {

        const message = await response.text();

        console.error("Storage upload failed:", message);

        throw new Error(
            "Unable to save the generated book."
        );

    }

}


async function downloadStorage(env, path) {

    const base = supabaseBase(env);

    const key = requiredEnv(
        env,
        "SUPABASE_SERVICE_ROLE_KEY"
    );

    const encodedPath = path
        .split("/")
        .map(encodeURIComponent)
        .join("/");

    const response = await fetch(

        base +
        "/storage/v1/object/" +
        PDF_BUCKET +
        "/" +
        encodedPath,

        {

            headers: {

                "apikey": key,

                "Authorization": "Bearer " + key

            }

        }

    );

    if (!response.ok) {

        throw new Error(
            "The requested book file is unavailable."
        );

    }

    return response;

}


/* =========================================================
   DEEPSEEK API
   ========================================================= */

function deepseekModel(env) {

    return env.DEEPSEEK_MODEL || "deepseek-v4-pro";

}


async function deepseekRequest(env, body) {

    const apiKey = requiredEnv(
        env,
        "DEEPSEEK_API_KEY"
    );

    const response = await fetch(
        DEEPSEEK_ENDPOINT,
        {

            method: "POST",

            headers: {

                "Authorization": "Bearer " + apiKey,

                "Content-Type": "application/json"

            },

            body: JSON.stringify({

                model: deepseekModel(env),

                ...body

            })

        }
    );

    if (!response.ok) {

        const message = await response.text();

        console.error(
            "DeepSeek API error:",
            response.status,
            message
        );

        throw new Error(
            "The AI writing service is temporarily unavailable."
        );

    }

    return response;

}


/* =========================================================
   BOOK OUTLINE GENERATION
   ========================================================= */

async function createBookOutline(env, userPrompt) {

    const system = `
You are the professional chief editor and book architect
for IDX ebook AI.

Your job is to plan a complete, original, professionally
written book.

The user's request is the complete creative brief.

Determine the appropriate genre, audience, tone,
structure and depth from the request.

Create a substantial book with 8 to 12 chapters.

Each chapter must have a distinct purpose and must
contribute meaningfully to the overall book.

Avoid repetition, filler and generic writing.

The book must be interesting, coherent and useful.

For fiction, create a compelling narrative with
consistent characters, believable development,
conflict and a satisfying conclusion.

For nonfiction, provide accurate, detailed,
well-organized explanations and practical examples.

Return ONLY valid JSON.

Required JSON structure:

{
  "title": "Book title",
  "subtitle": "Book subtitle",
  "description": "Book description",
  "genre": "Book genre",
  "audience": "Target audience",
  "tone": "Writing tone",
  "chapters": [
    {
      "title": "Chapter title",
      "purpose": "Chapter purpose",
      "key_points": [
        "Point one",
        "Point two"
      ]
    }
  ]
}
`;

    const response = await deepseekRequest(
        env,
        {

            messages: [

                {
                    role: "system",
                    content: system
                },

                {
                    role: "user",
                    content:
                        "Create a complete book plan for this request:\n\n" +
                        userPrompt
                }

            ],

            response_format: {
                type: "json_object"
            },

            temperature: 0.7,

            max_tokens: 5000

        }
    );

    const result = await response.json();

    const content =
        result.choices?.[0]?.message?.content;

    if (!content) {

        throw new Error(
            "The AI could not create the book outline."
        );

    }

    let outline;

    try {

        outline = JSON.parse(content);

    } catch {

        throw new Error(
            "The AI returned an invalid book outline."
        );

    }

    if (
        !outline.title ||
        !Array.isArray(outline.chapters) ||
        outline.chapters.length < 6
    ) {

        throw new Error(
            "The generated book outline is incomplete."
        );

    }

    outline.title = safeText(outline.title, 180);

    outline.subtitle = safeText(
        outline.subtitle,
        250
    );

    outline.description = safeText(
        outline.description,
        1200
    );

    outline.chapters = outline.chapters
        .slice(0, 12)
        .map(chapter => ({

            title: safeText(chapter.title, 180),

            purpose: safeText(chapter.purpose, 1500),

            key_points: Array.isArray(chapter.key_points)
                ? chapter.key_points
                    .slice(0, 10)
                    .map(point => safeText(point, 500))
                : []

        }));

    return outline;

}


/* =========================================================
   END OF PART 1
   ========================================================= */
   /* =========================================================
   IDX EBOOK AI
   PART 2 OF 4
   ========================================================= */


/* =========================================================
   STREAM DEEPSEEK CHAPTER CONTENT
   ========================================================= */

async function generateChapter(
    env,
    outline,
    chapter,
    index,
    total,
    userPrompt,
    onText
) {

    const system = `
You are a world-class professional book author,
editor and subject specialist working for IDX ebook AI.

Write a complete, substantial chapter of a book.

STRICT QUALITY REQUIREMENTS:

1. Write approximately 700-1000 meaningful words.
2. Do not summarize the chapter.
3. Do not repeat previous chapters.
4. Use natural, polished professional language.
5. Maintain consistent terminology and narrative continuity.
6. Use useful headings where appropriate.
7. Use detailed explanations, examples and illustrations
   where the subject requires them.
8. Avoid unnecessary introductions and conclusions.
9. Never invent facts, statistics or sources.
10. Do not mention AI or the generation process.
11. Do not use filler to increase word count.
12. Make the chapter genuinely valuable to readers.

The first chapter should establish the book's direction.

The final chapter should provide a satisfying conclusion
or meaningful synthesis.

Return the chapter itself, not commentary.
`;

    const prompt = `
BOOK TITLE:
${outline.title}

SUBTITLE:
${outline.subtitle || ""}

BOOK GENRE:
${outline.genre || ""}

TARGET AUDIENCE:
${outline.audience || ""}

WRITING TONE:
${outline.tone || ""}

ORIGINAL USER REQUEST:
${userPrompt}

CHAPTER:
${index + 1} OF ${total}

CHAPTER TITLE:
${chapter.title}

CHAPTER PURPOSE:
${chapter.purpose}

CHAPTER POINTS:
${chapter.key_points.join("\n")}

Write the complete chapter now.
`;

    const response = await deepseekRequest(
        env,
        {

            messages: [

                {
                    role: "system",
                    content: system
                },

                {
                    role: "user",
                    content: prompt
                }

            ],

            stream: true,

            temperature: 0.75,

            max_tokens: 3200

        }
    );

    const reader = response.body.getReader();

    const textDecoder = new TextDecoder();

    let buffer = "";

    let completeText = "";

    let finished = false;

    while (!finished) {

        const { value, done } = await reader.read();

        if (done) break;

        buffer += textDecoder.decode(
            value,
            { stream: true }
        );

        const lines = buffer.split(/\r?\n/);

        buffer = lines.pop() || "";

        for (const line of lines) {

            if (!line.startsWith("data:")) continue;

            const data = line.slice(5).trim();

            if (data === "[DONE]") {

                finished = true;

                break;

            }

            let chunk;

            try {

                chunk = JSON.parse(data);

            } catch {

                continue;

            }

            const content =
                chunk.choices?.[0]?.delta?.content;

            if (typeof content === "string" && content) {

                completeText += content;

                onText(content);

            }

        }

    }

    if (!completeText.trim()) {

        throw new Error(
            "DeepSeek returned an empty chapter."
        );

    }

    return completeText.trim();

}


/* =========================================================
   SERVER-SENT EVENTS
   ========================================================= */

function sendSSE(controller, event, payload) {

    const data = JSON.stringify(payload);

    controller.enqueue(

        encoder.encode(

            "event: " + event +
            "\n" +
            "data: " + data +
            "\n\n"

        )

    );

}


function emitText(controller, text) {

    sendSSE(
        controller,
        "delta",
        { text }
    );

}


/* =========================================================
   BOOK COVER GENERATOR

   Generates a real SVG cover image.

   No external image API is required for this cover.
   ========================================================= */

function createBookCoverSVG(book) {

    const title = escapeXML(book.title);

    const subtitle = escapeXML(
        book.subtitle || "A publication by IDX ebook AI"
    );

    const words = title.split(/\s+/);

    const lines = [];

    let current = "";

    for (const word of words) {

        const candidate = current
            ? current + " " + word
            : word;

        if (candidate.length > 20 && current) {

            lines.push(current);

            current = word;

        } else {

            current = candidate;

        }

    }

    if (current) lines.push(current);

    const titleLines = lines
        .slice(0, 5)
        .map((line, index) => {

            return `
                <text
                    x="500"
                    y="${430 + index * 78}"
                    text-anchor="middle"
                    class="title"
                >${escapeXML(line)}</text>
            `;

        })
        .join("");

    return `

<svg xmlns="http://www.w3.org/2000/svg"
     width="1000"
     height="1000"
     viewBox="0 0 1000 1000">

<defs>

    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">

        <stop offset="0%" stop-color="#160b28"/>

        <stop offset="55%" stop-color="#7135a1"/>

        <stop offset="100%" stop-color="#21102f"/>

    </linearGradient>

    <radialGradient id="glow">

        <stop offset="0%" stop-color="#d8a9ff" stop-opacity=".35"/>

        <stop offset="100%" stop-color="#d8a9ff" stop-opacity="0"/>

    </radialGradient>

</defs>

<style>

.title {
    fill: #ffffff;
    font-family: Georgia, serif;
    font-size: 65px;
    font-weight: bold;
}

.subtitle {
    fill: #e6cafa;
    font-family: Georgia, serif;
    font-size: 25px;
}

.brand {
    fill: #e3c2ff;
    font-family: Arial, sans-serif;
    font-size: 27px;
    font-weight: bold;
    letter-spacing: 5px;
}

</style>

<rect width="1000" height="1000" fill="url(#bg)"/>

<circle cx="800" cy="200" r="400" fill="url(#glow)"/>

<circle cx="200" cy="850" r="400" fill="url(#glow)"/>

<rect
    x="55"
    y="55"
    width="890"
    height="890"
    rx="8"
    fill="none"
    stroke="#e3c2ff"
    stroke-opacity=".65"
    stroke-width="3"
/>

<text x="500" y="175" text-anchor="middle" class="brand">
IDX EBOOK AI
</text>

<line
    x1="350"
    y1="230"
    x2="650"
    y2="230"
    stroke="#e3c2ff"
    stroke-width="2"
/>

${titleLines}

<text
    x="500"
    y="790"
    text-anchor="middle"
    class="subtitle"
>${subtitle}</text>

<text
    x="500"
    y="875"
    text-anchor="middle"
    class="brand"
    font-size="17"
>PROFESSIONALLY CREATED</text>

</svg>

`;

}


function bytesToBase64(bytes) {

    let binary = "";

    const chunkSize = 8192;

    for (
        let i = 0;
        i < bytes.length;
        i += chunkSize
    ) {

        binary += String.fromCharCode(
            ...bytes.subarray(
                i,
                i + chunkSize
            )
        );

    }

    return btoa(binary);

}


/* =========================================================
   PDF TEXT ENCODING

   Uses built-in PDF Helvetica fonts with WinAnsi encoding.
   ========================================================= */

function winAnsiBytes(text) {

    const special = {

        "€": 128,
        "‚": 130,
        "ƒ": 131,
        "„": 132,
        "…": 133,
        "†": 134,
        "‡": 135,
        "ˆ": 136,
        "‰": 137,
        "Š": 138,
        "‹": 139,
        "Œ": 140,
        "Ž": 142,
        "‘": 145,
        "’": 146,
        "“": 147,
        "”": 148,
        "•": 149,
        "–": 150,
        "—": 151,
        "˜": 152,
        "™": 153,
        "š": 154,
        "›": 155,
        "œ": 156,
        "ž": 158,
        "Ÿ": 159

    };

    const bytes = [];

    for (const char of String(text)) {

        const cp = char.codePointAt(0);

        if (special[char] !== undefined) {

            bytes.push(special[char]);

        } else if (
            cp <= 126 ||
            (cp >= 160 && cp <= 255)
        ) {

            bytes.push(cp);

        } else {

            bytes.push(63);

        }

    }

    return bytes;

}


function pdfHex(text) {

    return winAnsiBytes(text)
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("")
        .toUpperCase();

}


function pdfTextCommand(
    text,
    x,
    y,
    size,
    font = "F1"
) {

    return (
        "BT /" + font +
        " " + size +
        " Tf 1 0 0 1 " +
        x + " " + y +
        " Tm <" + pdfHex(text) +
        "> Tj ET\n"
    );

}


/* =========================================================
   TEXT WRAPPING
   ========================================================= */

function wrapPDFText(text, fontSize = 11.5) {

    const maxCharacters = Math.floor(
        500 / (fontSize * 0.53)
    );

    const words = String(text)
        .replace(/\s+/g, " ")
        .trim()
        .split(" ");

    const lines = [];

    let line = "";

    for (const word of words) {

        if (!word) continue;

        if (word.length > maxCharacters) {

            if (line) {

                lines.push(line);

                line = "";

            }

            for (
                let i = 0;
                i < word.length;
                i += maxCharacters
            ) {

                lines.push(
                    word.slice(i, i + maxCharacters)
                );

            }

            continue;

        }

        const candidate = line
            ? line + " " + word
            : word;

        if (candidate.length > maxCharacters && line) {

            lines.push(line);

            line = word;

        } else {

            line = candidate;

        }

    }

    if (line) lines.push(line);

    return lines;

}


/* =========================================================
   END OF PART 2
   ========================================================= */
   /* =========================================================
   IDX EBOOK AI
   PART 3 OF 4
   ========================================================= */


/* =========================================================
   PROFESSIONAL PDF GENERATOR

   A4 page dimensions:
   595.28 x 841.89 points.

   Body text:
   11.5 pt.

   Line spacing:
   17 pt.

   Margins:
   55 points.

   Uses built-in Helvetica fonts.
   ========================================================= */

function createPDF(book) {

    const PAGE_WIDTH = 595;

    const PAGE_HEIGHT = 842;

    const MARGIN = 55;

    const pages = [];

    function newPage() {

        pages.push("");

        return pages.length - 1;

    }

    function addText(
        page,
        text,
        x,
        y,
        size,
        font = "F1"
    ) {

        pages[page] += pdfTextCommand(
            text,
            x,
            y,
            size,
            font
        );

    }


    /* TITLE PAGE */

    let page = newPage();

    let titleLines = wrapPDFText(
        book.title,
        28
    );

    let titleY = 570 +
        (titleLines.length * 8);

    titleLines.forEach(line => {

        addText(
            page,
            line,
            65,
            titleY,
            28,
            "F2"
        );

        titleY -= 43;

    });

    if (book.subtitle) {

        const subtitleLines = wrapPDFText(
            book.subtitle,
            13
        );

        let subtitleY = titleY - 35;

        subtitleLines.forEach(line => {

            addText(
                page,
                line,
                65,
                subtitleY,
                13
            );

            subtitleY -= 21;

        });

    }

    addText(
        page,
        "IDX EBOOK AI",
        65,
        100,
        12,
        "F2"
    );


    /* TABLE OF CONTENTS */

    page = newPage();

    let y = PAGE_HEIGHT - 80;

    addText(
        page,
        "Table of Contents",
        MARGIN,
        y,
        24,
        "F2"
    );

    y -= 55;

    for (
        let i = 0;
        i < book.chapters.length;
        i++
    ) {

        const chapter = book.chapters[i];

        const lines = wrapPDFText(
            chapter.title,
            12
        );

        for (const line of lines) {

            if (y < 70) {

                page = newPage();

                y = PAGE_HEIGHT - 75;

            }

            addText(
                page,
                line,
                MARGIN,
                y,
                12,
                "F1"
            );

            y -= 24;

        }

    }


    /* CHAPTER CONTENT */

    for (
        let chapterIndex = 0;
        chapterIndex < book.chapters.length;
        chapterIndex++
    ) {

        const chapter = book.chapters[chapterIndex];

        page = newPage();

        y = PAGE_HEIGHT - 85;

        const headingLines = wrapPDFText(
            chapter.title,
            21
        );

        for (const line of headingLines) {

            addText(
                page,
                line,
                MARGIN,
                y,
                21,
                "F2"
            );

            y -= 30;

        }

        y -= 18;

        const paragraphs = String(chapter.content || "")
            .split(/\n+/)
            .map(p => p.trim())
            .filter(Boolean);

        for (const paragraph of paragraphs) {

            const lines = wrapPDFText(
                paragraph,
                11.5
            );

            for (const line of lines) {

                if (y < 65) {

                    page = newPage();

                    y = PAGE_HEIGHT - 65;

                }

                addText(
                    page,
                    line,
                    MARGIN,
                    y,
                    11.5,
                    "F1"
                );

                y -= 17;

            }

            y -= 10;

        }

    }


    /* PAGE NUMBERS */

    for (let i = 0; i < pages.length; i++) {

        pages[i] += pdfTextCommand(
            String(i + 1),
            PAGE_WIDTH / 2,
            27,
            9,
            "F1"
        );

    }


    /* PDF OBJECT ASSEMBLY */

    const objects = [];

    objects[1] =
        "<< /Type /Catalog /Pages 2 0 R >>";

    const pageRefs = [];

    for (let i = 0; i < pages.length; i++) {

        const pageObject = 5 + (i * 2);

        pageRefs.push(
            pageObject + " 0 R"
        );

    }

    objects[2] =
        "<< /Type /Pages /Kids [" +
        pageRefs.join(" ") +
        "] /Count " +
        pages.length +
        " >>";

    objects[3] =
        "<< /Type /Font /Subtype /Type1 " +
        "/BaseFont /Helvetica " +
        "/Encoding /WinAnsiEncoding >>";

    objects[4] =
        "<< /Type /Font /Subtype /Type1 " +
        "/BaseFont /Helvetica-Bold " +
        "/Encoding /WinAnsiEncoding >>";


    for (let i = 0; i < pages.length; i++) {

        const pageObject = 5 + (i * 2);

        const contentObject = pageObject + 1;

        const content = pages[i];

        objects[pageObject] =

            "<< /Type /Page " +
            "/Parent 2 0 R " +
            "/MediaBox [0 0 595 842] " +

            "/Resources << /Font << " +
            "/F1 3 0 R " +
            "/F2 4 0 R " +
            ">> >> " +

            "/Contents " +
            contentObject +
            " 0 R >>";


        objects[contentObject] =

            "<< /Length " +
            encoder.encode(content).length +
            " >>\n" +

            "stream\n" +

            content +

            "\nendstream";

    }


    let output = "%PDF-1.4\n";

    const offsets = [0];

    for (let i = 1; i < objects.length; i++) {

        offsets[i] = output.length;

        output +=
            i + " 0 obj\n" +
            objects[i] +
            "\nendobj\n";

    }

    const xrefPosition = output.length;

    output +=
        "xref\n0 " +
        objects.length +
        "\n";

    output +=
        "0000000000 65535 f \n";

    for (let i = 1; i < objects.length; i++) {

        output +=
            String(offsets[i])
                .padStart(10, "0") +
            " 00000 n \n";

    }

    output +=
        "trailer\n" +
        "<< /Size " +
        objects.length +
        " /Root 1 0 R >>\n" +

        "startxref\n" +

        xrefPosition +

        "\n%%EOF";

    return encoder.encode(output);

}


/* =========================================================
   COMPLETE BOOK GENERATION
   ========================================================= */

async function generateCompleteBook(
    env,
    ownerHash,
    userPrompt,
    controller
) {

    const emit = (event, data) => {

        sendSSE(controller, event, data);

    };

    emit(
        "delta",
        {
            text:
                "I'm planning your book and organizing its chapters.\n\n"
        }
    );

    const outline = await createBookOutline(
        env,
        userPrompt
    );

    const chapters = [];

    const total = outline.chapters.length;

    for (let i = 0; i < total; i++) {

        const chapter = outline.chapters[i];

        emitText(
            controller,
            "\n\n## " +
            chapter.title +
            "\n\n"
        );

        const content = await generateChapter(

            env,

            outline,

            chapter,

            i,

            total,

            userPrompt,

            text => emitText(controller,text)

        );

        chapters.push({

            title: chapter.title,

            content

        });

        emit(
            "delta",
            {
                text: "\n"
            }
        );

    }


    const bookId = uuid();

    const book = {

        id: bookId,

        title: outline.title,

        subtitle: outline.subtitle,

        description: outline.description,

        genre: outline.genre,

        chapters,

        content: chapters
            .map(chapter =>
                chapter.title + "\n\n" +
                chapter.content
            )
            .join("\n\n")

    };


    /* CREATE COVER */

    const coverSVG = createBookCoverSVG(book);

    const coverBytes = encoder.encode(coverSVG);

    const coverPath =
        "covers/" + bookId + ".svg";


    /* CREATE PDF */

    const pdfBytes = createPDF(book);

    const pdfPath =
        "books/" + bookId + ".pdf";


    /* SAVE FILES */

    await uploadStorage(
        env,
        coverPath,
        coverBytes,
        "image/svg+xml"
    );

    await uploadStorage(
        env,
        pdfPath,
        pdfBytes,
        "application/pdf"
    );


    /* SAVE BOOK RECORD */

    await dbInsert(
        env,
        "idx_books",
        {

            id: bookId,

            owner_hash: ownerHash,

            title: book.title,

            subtitle: book.subtitle,

            description: book.description,

            manuscript: {

                genre: book.genre,

                chapters: book.chapters

            },

            cover_path: coverPath,

            pdf_path: pdfPath,

            status: "completed"

        }
    );


    /* SEND BOOK TO FRONTEND */

    const coverDataUrl =
        "data:image/svg+xml;base64," +
        bytesToBase64(coverBytes);


    emit(
        "book_ready",
        {

            book: {

                id: book.id,

                title: book.title,

                subtitle: book.subtitle,

                description: book.description,

                chapters: book.chapters,

                coverDataUrl

            }

        }
    );

}


/* =========================================================
   CHAT ROUTE

   Matches index.html:

   POST /api/chat

   Body:
   {
       message,
       sessionId,
       history
   }

   Response:
   SSE stream

   Events:
   delta
   book_ready
   error
   ========================================================= */

async function handleChat(request, env) {

    if (!verifyOrigin(request)) {

        return fail("Invalid request origin.",403);

    }

    const session = await getSession(
        request,
        true
    );

    const body = await readJSON(request);

    const message = safeText(
        body.message,
        5000
    );

    if (!message || message.length < 5) {

        return fail(
            "Please describe the book you want to create."
        );

    }

    const stream = new ReadableStream({

        async start(controller) {

            try {

                await generateCompleteBook(

                    env,

                    session.ownerHash,

                    message,

                    controller

                );

            } catch(error) {

                console.error(
                    "Book generation error:",
                    error
                );

                sendSSE(
                    controller,
                    "error",
                    {
                        message:
                            error.message ||
                            "Book generation failed."
                    }
                );

            } finally {

                controller.close();

            }

        }

    });


    const headers = {

        "Content-Type": "text/event-stream; charset=utf-8",

        "Cache-Control": "no-cache, no-transform",

        "Connection": "keep-alive",

        "X-Accel-Buffering": "no"

    };

    if (session.created) {

        headers["Set-Cookie"] = sessionCookie(
            session,
            request
        );

    }

    return new Response(stream, {

        status: 200,

        headers

    });

}


/* =========================================================
   PAYMEGATE API HELPER
   ========================================================= */

async function paymegateRequest(
    env,
    path,
    options = {}
) {

    const apiKey = requiredEnv(
        env,
        "PAYMEGATE_API_KEY"
    );

    const response = await fetch(

        PAYMEGATE_ENDPOINT + path,

        {

            method: options.method || "GET",

            headers: {

                "X-API-Key": apiKey,

                "Content-Type": "application/json"

            },

            body: options.body
                ? JSON.stringify(options.body)
                : undefined

        }

    );

    const raw = await response.text();

    let result;

    try {

        result = raw
            ? JSON.parse(raw)
            : {};

    } catch {

        result = {};

    }

    if (!response.ok || result.success === false) {

        console.error(
            "Paymegate error:",
            response.status,
            result
        );

        throw new Error(
            result.error?.message ||
            "Payment service is unavailable."
        );

    }

    return result;

}


/* =========================================================
   CREATE PAYMENT

   Matches index.html:

   POST /api/payment/create

   Body:
   {
       bookId,
       sessionId,
       customerEmail
   }

   Response:
   {
       checkoutUrl,
       orderUUID
   }
   ========================================================= */

async function handlePaymentCreate(request, env) {

    if (!verifyOrigin(request)) {

        return fail("Invalid request origin.",403);

    }

    const session = await requireSession(request);

    const body = await readJSON(request);

    const bookId = safeText(
        body.bookId,
        80
    );

    const customerEmail = safeText(
        body.customerEmail,
        254
    );

    if (!validateEmail(customerEmail)) {

        return fail(
            "A valid customer email address is required."
        );

    }

    const book = await dbSelectOne(
        env,
        "idx_books",
        {

            id: bookId,

            owner_hash: session.ownerHash

        }
    );

    if (!book) {

        return fail(
            "This book could not be found.",
            404
        );

    }

    const paymentId = uuid();

    const externalId =
        "idx_" + paymentId.replace(/-/g,"");

    const origin = new URL(request.url).origin;

    if (!origin.startsWith("https://")) {

        return fail(
            "Secure HTTPS hosting is required for live payments.",
            400
        );

    }


    /* CREATE LOCAL PAYMENT RECORD */

    await dbInsert(
        env,
        "idx_payments",
        {

            id: paymentId,

            owner_hash: session.ownerHash,

            book_id: bookId,

            external_id: externalId,

            amount: PAYMENT_PRICE,

            currency: PAYMENT_CURRENCY,

            customer_email: customerEmail,

            status: "pending"

        }
    );


    try {

        const result = await paymegateRequest(
            env,
            "/v1/orders",
            {

                method: "POST",

                body: {

                    externalId,

                    amount: PAYMENT_PRICE,

                    currency: PAYMENT_CURRENCY,

                    paymentMethodsKeys: ["*"],

                    customer: {

                        email: customerEmail

                    },

                    description:
                        "IDX ebook AI - " + book.title,

                    backUrl:
                        origin +
                        "/?order=" +
                        paymentId,

                    metadata: {

                        app: APP_NAME,

                        bookId,

                        paymentId

                    }

                }

            }
        );

        const data = result.data;

        if (
            !data ||
            !data.orderUUID ||
            !data.checkoutUrl
        ) {

            throw new Error(
                "Paymegate returned an invalid checkout response."
            );

        }


        await dbUpdate(
            env,
            "idx_payments",
            {
                id: paymentId
            },
            {

                order_uuid: data.orderUUID,

                status: "pending"

            }
        );


        return json({

            success: true,

            checkoutUrl: data.checkoutUrl,

            orderUUID: data.orderUUID

        });

    } catch(error) {

        await dbUpdate(
            env,
            "idx_payments",
            {
                id: paymentId
            },
            {
                status: "failed"
            }
        );

        throw error;

    }

}


/* =========================================================
   END OF PART 3
   ========================================================= */
   /* =========================================================
   IDX EBOOK AI
   PART 4 OF 4
   ========================================================= */


/* =========================================================
   PAYMENT LOOKUP

   The return URL may contain the local payment ID.
   The browser may also supply the Paymegate order UUID.
   ========================================================= */

async function findPayment(env, identifier) {

    let payment = await dbSelectOne(
        env,
        "idx_payments",
        {
            id: identifier
        }
    );

    if (payment) return payment;

    payment = await dbSelectOne(
        env,
        "idx_payments",
        {
            order_uuid: identifier
        }
    );

    return payment;

}


/* =========================================================
   VERIFY PAYMENT DIRECTLY WITH PAYMEGATE

   Never trust a browser redirect as proof of payment.
   ========================================================= */

async function reconcilePayment(env, payment) {

    if (payment.status === "paid") {

        return true;

    }

    if (!payment.order_uuid) {

        return false;

    }

    const result = await paymegateRequest(

        env,

        "/v1/orders/" +
        encodeURIComponent(payment.order_uuid)

    );

    const order = result.data;

    if (!order) return false;

    const correctAmount =
        Number(order.amount) === 5;

    const correctCurrency =
        order.currency === "USD";

    const correctExternalId =
        order.externalId === payment.external_id;

    if (

        order.status === "PAID" &&

        correctAmount &&

        correctCurrency &&

        correctExternalId

    ) {

        await dbUpdate(
            env,
            "idx_payments",
            {
                id: payment.id
            },
            {

                status: "paid",

                paid_at: order.paidAt ||
                    new Date().toISOString()

            }
        );

        return true;

    }

    if (
        ["FAILED","EXPIRED","CANCELLED"].includes(
            order.status
        )
    ) {

        await dbUpdate(
            env,
            "idx_payments",
            {
                id: payment.id
            },
            {
                status: order.status.toLowerCase()
            }
        );

    }

    return false;

}


/* =========================================================
   PAYMENT STATUS ROUTE

   GET /api/payment/status?order=...

   Returns:

   {
       paid: true,
       bookId: "..."
   }

   ========================================================= */

async function handlePaymentStatus(request, env) {

    const session = await requireSession(request);

    const url = new URL(request.url);

    const identifier = safeText(
        url.searchParams.get("order"),
        100
    );

    if (!identifier) {

        return fail(
            "Payment order is missing."
        );

    }

    const payment = await findPayment(
        env,
        identifier
    );

    if (
        !payment ||
        payment.owner_hash !== session.ownerHash
    ) {

        return fail(
            "Payment record not found.",
            404
        );

    }

    if (payment.status === "paid") {

        return json({

            paid: true,

            status: "PAID",

            bookId: payment.book_id

        });

    }

    const paid = await reconcilePayment(
        env,
        payment
    );

    if (paid) {

        return json({

            paid: true,

            status: "PAID",

            bookId: payment.book_id

        });

    }

    const refreshed = await dbSelectOne(
        env,
        "idx_payments",
        {
            id: payment.id
        }
    );

    return json({

        paid: false,

        status: (
            refreshed?.status || "pending"
        ).toUpperCase(),

        bookId: payment.book_id

    });

}


/* =========================================================
   PAYMEGATE WEBHOOK SIGNATURE VERIFICATION

   Official specification:

   HMAC-SHA256(
       signingSecret,
       timestamp + "." + rawRequestBody
   )

   Output:
   Unpadded Base64URL.

   Timestamp replay protection: 5 minutes.
   ========================================================= */

function base64URL(bytes) {

    let binary = "";

    for (const byte of bytes) {

        binary += String.fromCharCode(byte);

    }

    return btoa(binary)
        .replace(/\+/g,"-")
        .replace(/\//g,"_")
        .replace(/=+$/,"");

}


function constantTimeEqual(a,b) {

    if (a.length !== b.length) return false;

    let difference = 0;

    for (let i = 0; i < a.length; i++) {

        difference |=
            a.charCodeAt(i) ^ b.charCodeAt(i);

    }

    return difference === 0;

}


async function verifyPaymegateSignature(
    secret,
    timestamp,
    rawBody,
    signature
) {

    const seconds = Number(timestamp);

    if (!Number.isFinite(seconds)) {

        return false;

    }

    const now = Math.floor(
        Date.now() / 1000
    );

    if (Math.abs(now - seconds) > 300) {

        return false;

    }

    const key = await crypto.subtle.importKey(

        "raw",

        encoder.encode(secret),

        {
            name: "HMAC",
            hash: "SHA-256"
        },

        false,

        ["sign"]

    );

    const signedData =
        timestamp + "." + rawBody;

    const digest = await crypto.subtle.sign(

        "HMAC",

        key,

        encoder.encode(signedData)

    );

    const expected = base64URL(
        new Uint8Array(digest)
    );

    return constantTimeEqual(
        expected,
        signature
    );

}


/* =========================================================
   PAYMEGATE WEBHOOK EVENT HANDLER

   POST /api/webhooks/paymegate

   ========================================================= */

async function handlePaymegateWebhook(
    request,
    env
) {

    const eventType = request.headers.get(
        "X-Paymegate-Event"
    );

    const eventId = request.headers.get(
        "X-Paymegate-Event-Id"
    );

    const timestamp = request.headers.get(
        "X-Paymegate-Timestamp"
    );

    const signature = request.headers.get(
        "X-Paymegate-Signature"
    );

    if (
        eventType !== "order.paid" ||
        !eventId ||
        !timestamp ||
        !signature
    ) {

        return fail(
            "Invalid webhook headers.",
            400
        );

    }

    const rawBody = await request.text();

    const secret = requiredEnv(
        env,
        "PAYMEGATE_WEBHOOK_SECRET"
    );

    const valid = await verifyPaymegateSignature(

        secret,

        timestamp,

        rawBody,

        signature

    );

    if (!valid) {

        return fail(
            "Webhook signature verification failed.",
            401
        );

    }

    let event;

    try {

        event = JSON.parse(rawBody);

    } catch {

        return fail(
            "Invalid webhook body.",
            400
        );

    }

    if (
        event.type !== "order.paid" ||
        event.id !== eventId ||
        event.status !== "PAID"
    ) {

        return fail(
            "Invalid payment event.",
            400
        );

    }


    /* IDEMPOTENCY */

    const inserted = await dbRequest(

        env,

        "idx_webhook_events",

        "on_conflict=id",

        {

            method: "POST",

            headers: {

                "Prefer":
                    "resolution=ignore-duplicates,return=representation"

            },

            body: {

                id: eventId,

                status: "processing",

                received_at: new Date().toISOString()

            }

        }

    );

    if (!inserted || inserted.length === 0) {

        const existing = await dbSelectOne(

            env,

            "idx_webhook_events",

            {
                id: eventId
            }

        );

        if (existing?.status === "processed") {

            return new Response("OK", {
                status: 200
            });

        }

    }


    /* MATCH LOCAL PAYMENT */

    const payment = await dbSelectOne(

        env,

        "idx_payments",

        {
            external_id: event.externalId
        }

    );

    if (!payment) {

        return fail(
            "Matching payment was not found.",
            404
        );

    }

    if (
        payment.order_uuid !== event.orderUUID ||
        payment.amount !== PAYMENT_PRICE ||
        payment.currency !== PAYMENT_CURRENCY ||
        Number(event.amount) !== 5 ||
        event.currency !== "USD"
    ) {

        return fail(
            "Payment information does not match.",
            400
        );

    }

    if (
        event.metadata?.bookId &&
        event.metadata.bookId !== payment.book_id
    ) {

        return fail(
            "Book payment reference does not match.",
            400
        );

    }


    /* MARK PAID */

    if (payment.status !== "paid") {

        await dbUpdate(

            env,

            "idx_payments",

            {
                id: payment.id
            },

            {

                status: "paid",

                paid_at: event.paidAt ||
                    new Date().toISOString(),

                transaction_uuid:
                    event.transactionUUID || null

            }

        );

    }


    /* MARK EVENT PROCESSED */

    await dbUpdate(

        env,

        "idx_webhook_events",

        {
            id: eventId
        },

        {
            status: "processed"
        }

    );


    return new Response("OK", {

        status: 200,

        headers: {
            "Content-Type": "text/plain"
        }

    });

}


/* =========================================================
   PROTECTED PDF DOWNLOAD

   GET /api/books/:id/pdf

   Requirements:

   1. Valid anonymous session.
   2. Book belongs to that session.
   3. A matching payment is PAID.
   4. PDF exists in private Supabase Storage.

   ========================================================= */

async function handlePDFDownload(
    request,
    env,
    bookId
) {

    const session = await requireSession(request);

    const book = await dbSelectOne(

        env,

        "idx_books",

        {

            id: bookId,

            owner_hash: session.ownerHash

        }

    );

    if (!book) {

        return fail(
            "Book not found.",
            404
        );

    }


    const payment = await dbSelectOne(

        env,

        "idx_payments",

        {

            book_id: bookId,

            owner_hash: session.ownerHash,

            status: "paid"

        }

    );

    if (!payment) {

        return fail(
            "Payment is required before downloading this book.",
            402
        );

    }


    const file = await downloadStorage(

        env,

        book.pdf_path

    );

    const safeFilename = (

        book.title || "IDX ebook AI Book"

    )

        .replace(/[^a-zA-Z0-9 _-]/g,"")

        .trim()

        .slice(0,100) || "IDX-Book";


    return new Response(file.body, {

        status: 200,

        headers: {

            "Content-Type": "application/pdf",

            "Content-Disposition":
                'attachment; filename="' +
                safeFilename +
                '.pdf"',

            "Cache-Control": "private, no-store",

            "X-Content-Type-Options": "nosniff"

        }

    });

}


/* =========================================================
   ROUTER

   Cloudflare file:

   functions/api/[[route]].js

   Routes:

   POST /api/chat

   POST /api/payment/create

   GET /api/payment/status

   POST /api/webhooks/paymegate

   GET /api/books/:id/pdf

   ========================================================= */

async function routeRequest(context) {

    const request = context.request;

    const env = context.env;

    const route = Array.isArray(
        context.params?.route
    )

        ? context.params.route

        : [];

    const path = route.join("/");

    const method = request.method.toUpperCase();


    try {

        if (
            method === "POST" &&
            path === "chat"
        ) {

            return await handleChat(
                request,
                env
            );

        }


        if (
            method === "POST" &&
            path === "payment/create"
        ) {

            return await handlePaymentCreate(
                request,
                env
            );

        }


        if (
            method === "GET" &&
            path === "payment/status"
        ) {

            return await handlePaymentStatus(
                request,
                env
            );

        }


        if (
            method === "POST" &&
            path === "webhooks/paymegate"
        ) {

            return await handlePaymegateWebhook(
                request,
                env
            );

        }


        if (
            method === "GET" &&
            route.length === 3 &&
            route[0] === "books" &&
            route[2] === "pdf"
        ) {

            return await handlePDFDownload(
                request,
                env,
                route[1]
            );

        }


        return fail(
            "API route not found.",
            404
        );

    } catch(error) {

        console.error(
            "IDX ebook AI backend error:",
            error
        );

        return fail(

            error.message ||
            "An unexpected server error occurred.",

            500

        );

    }

}


/* =========================================================
   CLOUDFLARE PAGES ENTRY POINT
   ========================================================= */

export async function onRequest(context) {

    return routeRequest(context);

}


/* =========================================================
   END OF PART 4

   IDX EBOOK AI BACKEND
   ========================================================= */