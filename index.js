const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();

/* =========================================================
CONFIGURATION
========================================================= */

const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;

const SESSION_SECRET =
process.env.SESSION_SECRET ||
crypto.randomBytes(32).toString("hex");

const REDIRECT_URL =
"https://wa.me/918099188409?text=Hello%20Developer,%20please%20activate%20my%20app";

const ONLINE_TIMEOUT_MS = 25000;

const DASHBOARD_REFRESH_SECONDS = 15;

const DEVICES_PER_PAGE = 20;

/* =========================================================
HARD FAIL SECURITY CHECK
========================================================= */

if (!MONGO_URI) {
console.error("FATAL ERROR: MONGO_URI is missing.");
process.exit(1);
}

if (!ADMIN_PASSWORD && !ADMIN_PASSWORD_HASH) {
console.error(
"FATAL ERROR: ADMIN_PASSWORD or ADMIN_PASSWORD_HASH is required."
);
process.exit(1);
}

/* =========================================================
EXPRESS SETUP
========================================================= */

app.set("trust proxy", 1);

app.use(express.urlencoded({
extended: true,
limit: "100kb"
}));

app.use(express.json({
limit: "100kb"
}));

/* =========================================================
BASIC SECURITY HEADERS
========================================================= */

app.use((req, res, next) => {

res.setHeader(
    "X-Content-Type-Options",
    "nosniff"
);

res.setHeader(
    "X-Frame-Options",
    "DENY"
);

res.setHeader(
    "Referrer-Policy",
    "same-origin"
);

res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, private"
);

res.setHeader(
    "Pragma",
    "no-cache"
);

res.setHeader(
    "Expires",
    "0"
);

next();

});

/* =========================================================
MONGODB SESSION STORE
========================================================= */

app.use(
session({

    name: "admin.sid",

    secret: SESSION_SECRET,

    resave: false,

    saveUninitialized: false,

    store: MongoStore.create({

        mongoUrl: MONGO_URI,

        collectionName: "admin_sessions",

        ttl: 60 * 60 * 24

    }),

    cookie: {

        httpOnly: true,

        secure:
            process.env.NODE_ENV === "production",

        sameSite: "lax",

        maxAge:
            1000 * 60 * 60 * 24

    }

})

);

/* =========================================================
RATE LIMITERS
========================================================= */

const loginLimiter = rateLimit({

windowMs: 15 * 60 * 1000,

max: 10,

standardHeaders: true,

legacyHeaders: false,

message:
    "Too many login attempts. Please try again later."

});

const trackingLimiter = rateLimit({

windowMs: 60 * 1000,

max: 300,

standardHeaders: true,

legacyHeaders: false

});

/* =========================================================
DATABASE SCHEMAS
========================================================= */

const DeviceSchema = new mongoose.Schema({

deviceId: {

    type: String,

    required: true,

    unique: true,

    index: true,

    trim: true

},

nickname: {

    type: String,

    default: "",

    trim: true,

    maxlength: 50

},

status: {

    type: String,

    enum: [
        "pending",
        "approved",
        "blocked"
    ],

    default: "pending",

    index: true

},

registeredAt: {

    type: Date,

    default: Date.now

}

},
{
versionKey: false
});

const SessionSchema = new mongoose.Schema({

deviceId: {

    type: String,

    required: true,

    index: true

},

startTime: Date,

lastSeenTime: Date,

startTimestamp: {

    type: Number,

    index: true

},

lastSeenTimestamp: {

    type: Number,

    index: true

},

status: {

    type: String,

    enum: [
        "online",
        "offline"
    ],

    default: "online",

    index: true

}

},
{
versionKey: false
});

SessionSchema.index({

deviceId: 1,

status: 1,

startTimestamp: -1

});

SessionSchema.index({

startTimestamp: -1

});

const Device =
mongoose.model(
"Device",
DeviceSchema
);

const UsageSession =
mongoose.model(
"UsageSession",
SessionSchema
);

/* =========================================================
MONGODB CONNECTION
========================================================= */

mongoose.connect(
MONGO_URI,
{
serverSelectionTimeoutMS: 10000
}
)
.then(() => {

console.log(
    "MongoDB CONNECTED"
);

})
.catch((err) => {

console.error(
    "MongoDB CONNECTION FAILED:",
    err.message
);

});

mongoose.connection.on(
"error",
(err) => {

    console.error(
        "MongoDB Error:",
        err.message
    );

}

);

/* =========================================================
HELPERS
========================================================= */

function escapeHtml(value) {

return String(value ?? "")

    .replace(/&/g, "&amp;")

    .replace(/</g, "&lt;")

    .replace(/>/g, "&gt;")

    .replace(/"/g, "&quot;")

    .replace(/'/g, "&#039;");

}

function formatDuration(ms) {

if (
    !Number.isFinite(ms) ||
    ms < 0
) {
    return "0s";
}

const totalSeconds =
    Math.floor(ms / 1000);

const days =
    Math.floor(
        totalSeconds / 86400
    );

const hours =
    Math.floor(
        (totalSeconds % 86400) /
        3600
    );

const minutes =
    Math.floor(
        (totalSeconds % 3600) /
        60
    );

const seconds =
    totalSeconds % 60;

const result = [];

if (days > 0)
    result.push(days + "d");

if (hours > 0)
    result.push(hours + "h");

if (minutes > 0)
    result.push(minutes + "m");

if (
    seconds > 0 ||
    result.length === 0
) {
    result.push(seconds + "s");
}

return result.join(" ");

}

function safeDate(value) {

if (!value)
    return "N/A";

const date =
    new Date(value);

if (
    isNaN(date.getTime())
) {
    return String(value);
}

return date.toLocaleString(
    "en-IN",
    {

        timeZone:
            "Asia/Kolkata",

        dateStyle:
            "medium",

        timeStyle:
            "medium"

    }
);

}

function getISTStartOfDay() {

const now = new Date();

const formatter =
    new Intl.DateTimeFormat(
        "en-CA",
        {
            timeZone:
                "Asia/Kolkata",

            year: "numeric",

            month: "2-digit",

            day: "2-digit"
        }
    );

const parts =
    formatter.formatToParts(now);

const values = {};

parts.forEach((part) => {

    if (
        part.type !== "literal"
    ) {

        values[
            part.type
        ] = part.value;

    }

});

const istMidnightUTC =
    Date.UTC(

        Number(values.year),

        Number(values.month) - 1,

        Number(values.day),

        0,

        0,

        0

    ) -

    (
        5.5 *
        60 *
        60 *
        1000
    );

return istMidnightUTC;

}

function getRange(
filter,
customFrom,
customTo
) {

const now =
    Date.now();

let from =
    null;

let to =
    now;


if (
    filter === "today"
) {

    from =
        getISTStartOfDay();

}


if (
    filter === "7d"
) {

    from =
        now -
        (
            7 *
            24 *
            60 *
            60 *
            1000
        );

}


if (
    filter === "30d"
) {

    from =
        now -
        (
            30 *
            24 *
            60 *
            60 *
            1000
        );

}


if (
    filter === "custom"
) {

    if (customFrom) {

        const parsed =
            new Date(
                customFrom +
                "T00:00:00+05:30"
            );

        if (
            !isNaN(
                parsed.getTime()
            )
        ) {

            from =
                parsed.getTime();

        }

    }


    if (customTo) {

        const parsed =
            new Date(
                customTo +
                "T23:59:59.999+05:30"
            );

        if (
            !isNaN(
                parsed.getTime()
            )
        ) {

            to =
                parsed.getTime();

        }

    }

}


return {
    from,
    to
};

}

/* =========================================================
CSRF
========================================================= */

function csrfProtection(
req,
res,
next
) {

if (
    !req.session
) {

    return res
        .status(500)
        .send(
            "Session unavailable."
        );

}


if (
    !req.session.csrfToken
) {

    req.session.csrfToken =
        crypto
            .randomBytes(24)
            .toString("hex");

}


res.locals.csrfToken =
    req.session.csrfToken;


if (
    req.method === "GET"
) {

    return next();

}


if (
    req.method === "POST"
) {

    const token =
        req.body._csrf;

    if (
        !token ||
        token !==
        req.session.csrfToken
    ) {

        return res
            .status(403)
            .send(
                "CSRF validation failed."
            );

    }

}


next();

}

/* =========================================================
AUTH
========================================================= */

function requireLogin(
req,
res,
next
) {

if (
    req.session &&
    req.session.adminAuthenticated
) {

    return next();

}

return res.redirect(
    "/login"
);

}

/* =========================================================
SESSION CLEANUP
========================================================= */

async function markStaleSessionsOffline() {

try {

    const cutoff =
        Date.now() -
        ONLINE_TIMEOUT_MS;


    await UsageSession.updateMany(

        {

            status:
                "online",

            lastSeenTimestamp:
                {
                    $lt:
                        cutoff
                }

        },

        {

            $set:
                {
                    status:
                        "offline"
                }

        }

    );

}
catch (err) {

    console.error(
        "Session cleanup error:",
        err.message
    );

}

}

setInterval(

markStaleSessionsOffline,

15000

);

/* =========================================================
LOGIN PAGE
========================================================= */

app.get(

"/login",

csrfProtection,

(req, res) => {

    if (
        req.session &&
        req.session.adminAuthenticated
    ) {

        return res.redirect(
            "/"
        );

    }


    res.send(`

<!DOCTYPE html><html><head><meta charset="UTF-8"><meta
name="viewport"
content="width=device-width, initial-scale=1.0">

<title>Admin Login</title><style>

* {
box-sizing:border-box;
font-family:system-ui,sans-serif;
}

body {
margin:0;
min-height:100vh;
display:flex;
align-items:center;
justify-content:center;
background:#0f172a;
color:#e2e8f0;
padding:20px;
}

.card {
width:100%;
max-width:400px;
background:#1e293b;
padding:28px;
border-radius:14px;
box-shadow:
0 20px 60px
rgba(0,0,0,.4);
}

h1 {
text-align:center;
margin-top:0;
color:#38bdf8;
}

input {
width:100%;
padding:12px;
margin:8px 0;
border-radius:7px;
border:
1px solid #475569;
background:#0f172a;
color:white;
}

button {
width:100%;
padding:12px;
border:0;
border-radius:7px;
background:#3b82f6;
color:white;
font-weight:bold;
cursor:pointer;
margin-top:10px;
}

.error {
background:#7f1d1d;
padding:10px;
border-radius:6px;
text-align:center;
margin-bottom:10px;
color:#fecaca;
}

</style></head><body><div class="card"><h1>Secure Admin Login</h1>${
req.query.error
?
`<div class="error">
Invalid credentials

</div>`
:
""
}<form
method="POST"
action="/login"><input
type="hidden"
name="_csrf"
value="${escapeHtml(res.locals.csrfToken)}">

<input
type="text"
name="username"
placeholder="Username"
autocomplete="username"
required>

<input
type="password"
name="password"
placeholder="Password"
autocomplete="current-password"
required>

<button
type="submit">

Login

</button></form></div></body></html>    `);

}

);

/* =========================================================
LOGIN POST
========================================================= */

app.post(

"/login",

loginLimiter,

csrfProtection,

async (
    req,
    res
) => {

    try {

        const username =
            String(
                req.body.username ||
                ""
            )
            .trim();


        const password =
            String(
                req.body.password ||
                ""
            );


        if (
            username !==
            ADMIN_USERNAME
        ) {

            return res.redirect(
                "/login?error=1"
            );

        }


        let valid =
            false;


        if (
            ADMIN_PASSWORD_HASH
        ) {

            valid =
                await bcrypt.compare(
                    password,
                    ADMIN_PASSWORD_HASH
                );

        }
        else {

            valid =
                crypto.timingSafeEqual(

                    Buffer.from(
                        password
                    ),

                    Buffer.from(
                        ADMIN_PASSWORD
                    )

                );

        }


        if (!valid) {

            return res.redirect(
                "/login?error=1"
            );

        }


        req.session.regenerate(
            (err) => {

                if (err) {

                    console.error(
                        "Session regenerate error:",
                        err.message
                    );

                    return res.redirect(
                        "/login?error=1"
                    );

                }


                req.session.adminAuthenticated =
                    true;


                req.session.adminUsername =
                    ADMIN_USERNAME;


                req.session.csrfToken =
                    crypto
                        .randomBytes(24)
                        .toString("hex");


                req.session.save(
                    () => {

                        res.redirect(
                            "/"
                        );

                    }
                );

            }
        );

    }
    catch (err) {

        console.error(
            "Login error:",
            err.message
        );

        res.redirect(
            "/login?error=1"
        );

    }

}

);

/* =========================================================
LOGOUT
========================================================= */

app.post(

"/logout",

requireLogin,

csrfProtection,

(
    req,
    res
) => {

    req.session.destroy(
        () => {

            res.clearCookie(
                "admin.sid"
            );

            res.redirect(
                "/login"
            );

        }
    );

}

);

/* =========================================================
HEALTH CHECK
========================================================= */

app.get(

"/health",

(
    req,
    res
) => {

    const connected =
        mongoose.connection.readyState === 1;


    res
        .status(
            connected
                ? 200
                : 503
        )
        .json({

            server:
                "online",

            database:
                connected
                    ? "connected"
                    : "disconnected",

            timestamp:
                new Date()

        });

}

);

/* =========================================================
PUBLIC APP TRACKING
========================================================= */

async function handleTracking(
req,
res
) {

const deviceId =
    String(

        req.query.id ||

        req.body.id ||

        ""

    )
    .trim();


const action =
    String(

        req.query.action ||

        req.body.action ||

        "start"

    )
    .trim()
    .toLowerCase();


if (!deviceId) {

    return res
        .status(400)
        .json({

            status:
                "ERROR",

            message:
                "DEVICE_ID_MISSING"

        });

}


if (
    deviceId.length > 200
) {

    return res
        .status(400)
        .json({

            status:
                "ERROR"

        });

}


try {

    if (
        mongoose.connection.readyState !== 1
    ) {

        return res
            .status(503)
            .json({

                status:
                    "ERROR",

                message:
                    "DATABASE_OFFLINE"

            });

    }


    let device =
        await Device.findOne({

            deviceId

        });


    if (!device) {

        try {

            device =
                await Device.create({

                    deviceId,

                    status:
                        "pending",

                    registeredAt:
                        new Date()

                });

        }
        catch (err) {

            device =
                await Device.findOne({

                    deviceId

                });

        }


        return res
            .status(200)
            .json({

                status:
                    "BLOCKED",

                redirectUrl:
                    REDIRECT_URL

            });

    }


    if (
        device.status !== "approved"
    ) {

        await UsageSession.updateMany(

            {

                deviceId,

                status:
                    "online"

            },

            {

                $set:
                    {

                        status:
                            "offline"

                    }

            }

        );


        return res
            .status(200)
            .json({

                status:
                    "BLOCKED",

                redirectUrl:
                    REDIRECT_URL

            });

    }


    const now =
        Date.now();


    if (
        action === "stop"
    ) {

        const activeSession =
            await UsageSession.findOne({

                deviceId,

                status:
                    "online"

            })
            .sort({

                startTimestamp:
                    -1

            });


        if (
            activeSession
        ) {

            activeSession.lastSeenTimestamp =
                now;


            activeSession.lastSeenTime =
                new Date(now);


            activeSession.status =
                "offline";


            await activeSession.save();

        }


        return res
            .status(200)
            .json({

                status:
                    "ALLOWED",

                action:
                    "STOPPED"

            });

    }


    const activeSession =
        await UsageSession.findOneAndUpdate(

            {

                deviceId,

                status:
                    "online"

            },

            {

                $set:
                    {

                        lastSeenTimestamp:
                            now,

                        lastSeenTime:
                            new Date(now)

                    }

            },

            {

                sort:
                    {

                        startTimestamp:
                            -1

                    },

                new:
                    true

            }

        );


    if (!activeSession) {

        await UsageSession.create({

            deviceId,

            startTime:
                new Date(now),

            lastSeenTime:
                new Date(now),

            startTimestamp:
                now,

            lastSeenTimestamp:
                now,

            status:
                "online"

        });

    }


    return res
        .status(200)
        .json({

            status:
                "ALLOWED",

            action:
                activeSession
                    ? "HEARTBEAT"
                    : "STARTED"

        });

}
catch (err) {

    console.error(
        "Tracking error:",
        err.message
    );

    return res
        .status(500)
        .json({

            status:
                "ERROR"

        });

}

}

app.get(

[
    "/track",
    "/index.php"
],

trackingLimiter,

handleTracking

);

app.post(

[
    "/track",
    "/index.php"
],

trackingLimiter,

handleTracking

);

/* =========================================================
ADMIN ACTIONS
========================================================= */

app.post(

"/action/:type",

requireLogin,

csrfProtection,

async (
    req,
    res
) => {

    const type =
        String(
            req.params.type ||
            ""
        );


    const deviceId =
        String(
            req.body.deviceId ||
            ""
        )
        .trim();


    if (!deviceId) {

        return res.redirect(
            req.get("referer") ||
            "/"
        );

    }


    try {

        if (
            type === "nickname"
        ) {

            const nickname =
                String(
                    req.body.nickname ||
                    ""
                )
                .trim()
                .substring(
                    0,
                    50
                );


            await Device.updateOne(

                {
                    deviceId
                },

                {

                    $set:
                        {
                            nickname
                        }

                }

            );

        }


        if (
            type === "approve"
        ) {

            await Device.updateOne(

                {
                    deviceId
                },

                {

                    $set:
                        {
                            status:
                                "approved"
                        }

                }

            );

        }


        if (
            type === "pending"
        ) {

            await Device.updateOne(

                {
                    deviceId
                },

                {

                    $set:
                        {
                            status:
                                "pending"
                        }

                }

            );


            await UsageSession.updateMany(

                {

                    deviceId,

                    status:
                        "online"

                },

                {

                    $set:
                        {
                            status:
                                "offline"
                        }

                }

            );

        }


        if (
            type === "block"
        ) {

            await Device.updateOne(

                {
                    deviceId
                },

                {

                    $set:
                        {
                            status:
                                "blocked"
                        }

                }

            );


            await UsageSession.updateMany(

                {

                    deviceId,

                    status:
                        "online"

                },

                {

                    $set:
                        {
                            status:
                                "offline"
                        }

                }

            );

        }


        if (
            type === "delete"
        ) {

            await Device.deleteOne({

                deviceId

            });


            await UsageSession.deleteMany({

                deviceId

            });

        }

    }
    catch (err) {

        console.error(
            "Admin action error:",
            err.message
        );

    }


    res.redirect(
        req.get("referer") ||
        "/"
    );

}

);

/* =========================================================
DASHBOARD DATA API
========================================================= */

app.get(

"/api/dashboard",

requireLogin,

async (
    req,
    res
) => {

    try {

        await markStaleSessionsOffline();


        const search =
            String(
                req.query.search ||
                ""
            )
            .trim()
            .toLowerCase();


        const filter =
            String(
                req.query.filter ||
                "all"
            );


        const customFrom =
            String(
                req.query.from ||
                ""
            );


        const customTo =
            String(
                req.query.to ||
                ""
            );


        const requestedPage =
            Math.max(

                1,

                parseInt(
                    req.query.page ||
                    "1"
                ) || 1

            );


        const range =
            getRange(

                filter,

                customFrom,

                customTo

            );


        const matchStage =
            {};


        if (
            range.from !== null
        ) {

            matchStage.startTimestamp =
                {

                    $gte:
                        range.from,

                    $lte:
                        range.to

                };

        }


        const now =
            Date.now();


        /*
         * DATABASE-LEVEL AGGREGATION
         * No loading thousands of sessions into Node RAM.
         */

        const statsPromise =
            UsageSession.aggregate([

                {

                    $match:
                        matchStage

                },

                {

                    $project:
                        {

                            deviceId:
                                1,

                            status:
                                1,

                            duration:
                                {

                                    $max:
                                        [

                                            0,

                                            {

                                                $subtract:
                                                    [

                                                        {

                                                            $cond:
                                                                [

                                                                    {

                                                                        $and:
                                                                            [

                                                                                {

                                                                                    $eq:
                                                                                        [
                                                                                            "$status",
                                                                                            "online"
                                                                                        ]

                                                                                },

                                                                                {

                                                                                    $gt:
                                                                                        [
                                                                                            now - {

                                                                                                $ifNull:
                                                                                                    [
                                                                                                        "$lastSeenTimestamp",
                                                                                                        "$startTimestamp"
                                                                                                    ]

                                                                                            },

                                                                                            0
                                                                                        ]

                                                                                }

                                                                            ]

                                                                    },

                                                                    now,

                                                                    {

                                                                        $ifNull:
                                                                            [
                                                                                "$lastSeenTimestamp",
                                                                                "$startTimestamp"
                                                                            ]

                                                                    }

                                                                ]

                                                        },

                                                        "$startTimestamp"

                                                    ]

                                            }

                                        ]

                                }

                        }

                },

                {

                    $group:
                        {

                            _id:
                                "$deviceId",

                            totalUsage:
                                {
                                    $sum:
                                        "$duration"
                                },

                            sessionCount:
                                {
                                    $sum:
                                        1
                                },

                            isOnline:
                                {

                                    $max:
                                        {

                                            $cond:
                                                [

                                                    {

                                                        $eq:
                                                            [
                                                                "$status",
                                                                "online"
                                                            ]

                                                    },

                                                    1,

                                                    0

                                                ]

                                        }

                                }

                        }

                }

            ]);


        const chartPromise =
            UsageSession.aggregate([

                {

                    $match:
                        matchStage

                },

                {

                    $project:
                        {

                            day:
                                {

                                    $dateToString:
                                        {

                                            format:
                                                "%Y-%m-%d",

                                            date:
                                                "$startTime",

                                            timezone:
                                                "Asia/Kolkata"

                                        }

                                },

                            duration:
                                {

                                    $max:
                                        [

                                            0,

                                            {

                                                $subtract:
                                                    [

                                                        {

                                                            $ifNull:
                                                                [
                                                                    "$lastSeenTimestamp",
                                                                    "$startTimestamp"
                                                                ]

                                                        },

                                                        "$startTimestamp"

                                                    ]

                                            }

                                        ]

                                }

                        }

                },

                {

                    $group:
                        {

                            _id:
                                "$day",

                            usage:
                                {
                                    $sum:
                                        "$duration"
                                }

                        }

                },

                {

                    $sort:
                        {
                            _id:
                                1
                        }

                }

            ]);


        const devicesPromise =
            Device.find()
            .sort({

                registeredAt:
                    -1

            })
            .lean();


        const results =
            await Promise.all([

                statsPromise,

                chartPromise,

                devicesPromise

            ]);


        const stats =
            results[0];


        const chart =
            results[1];


        const devices =
            results[2];


        const statsMap =
            {};


        let totalUsage =
            0;


        let onlineCount =
            0;


        stats.forEach((stat) => {

            statsMap[
                stat._id
            ] =
                stat;


            totalUsage +=
                Number(
                    stat.totalUsage ||
                    0
                );


            if (
                stat.isOnline
            ) {

                onlineCount++;

            }

        });


        const searchedDevices =
            devices.filter((device) => {

                if (!search)
                    return true;


                return (

                    String(
                        device.deviceId
                    )
                    .toLowerCase()
                    .includes(search)

                    ||

                    String(
                        device.nickname ||
                        ""
                    )
                    .toLowerCase()
                    .includes(search)

                    ||

                    String(
                        device.status
                    )
                    .toLowerCase()
                    .includes(search)

                );

            });


        const totalPages =
            Math.max(

                1,

                Math.ceil(
                    searchedDevices.length /
                    DEVICES_PER_PAGE
                )

            );


        const page =
            Math.min(

                requestedPage,

                totalPages

            );


        const startIndex =
            (
                page - 1
            ) *
            DEVICES_PER_PAGE;


        const paginatedDevices =
            searchedDevices.slice(

                startIndex,

                startIndex +
                DEVICES_PER_PAGE

            );


        const totalDevices =
            devices.length;


        const approved =
            devices.filter(

                (device) =>
                    device.status ===
                    "approved"

            ).length;


        const pending =
            devices.filter(

                (device) =>
                    device.status ===
                    "pending"

            ).length;


        const blocked =
            devices.filter(

                (device) =>
                    device.status ===
                    "blocked"

            ).length;


        const deviceData =
            paginatedDevices.map(

                (device) => {

                    const stat =
                        statsMap[
                            device.deviceId
                        ] ||
                        {

                            totalUsage:
                                0,

                            sessionCount:
                                0,

                            isOnline:
                                0

                        };


                    return {

                        deviceId:
                            device.deviceId,

                        nickname:
                            device.nickname ||
                            "",

                        status:
                            device.status,

                        registeredAt:
                            safeDate(
                                device.registeredAt
                            ),

                        usage:
                            formatDuration(
                                Number(
                                    stat.totalUsage ||
                                    0
                                )
                            ),

                        sessions:
                            Number(
                                stat.sessionCount ||
                                0
                            ),

                        online:
                            Boolean(
                                stat.isOnline
                            )

                    };

                }

            );


        const chartLabels =
            chart.map(
                (item) =>
                    item._id
            );


        const chartData =
            chart.map(

                (item) =>
                    Math.round(
                        Number(
                            item.usage ||
                            0
                        ) /
                        60000
                    )

            );


        res.json({

            success:
                true,

            stats:
                {

                    totalDevices,

                    approved,

                    pending,

                    blocked,

                    online:
                        onlineCount,

                    totalUsage:
                        formatDuration(
                            totalUsage
                        )

                },

            devices:
                deviceData,

            pagination:
                {

                    page,

                    totalPages,

                    totalDevices:
                        searchedDevices.length

                },

            chart:
                {

                    labels:
                        chartLabels,

                    data:
                        chartData

                }

        });

    }
    catch (err) {

        console.error(
            "Dashboard API error:",
            err.message
        );


        res
            .status(500)
            .json({

                success:
                    false,

                error:
                    "DASHBOARD_ERROR"

            });

    }

}

);

/* =========================================================
MAIN DASHBOARD
========================================================= */

app.get(

"/",

requireLogin,

csrfProtection,

(
    req,
    res
) => {

    const search =
        String(
            req.query.search ||
            ""
        );


    const filter =
        String(
            req.query.filter ||
            "all"
        );


    const customFrom =
        String(
            req.query.from ||
            ""
        );


    const customTo =
        String(
            req.query.to ||
            ""
        );


    const page =
        Math.max(

            1,

            parseInt(
                req.query.page ||
                "1"
            ) || 1

        );


    res.send(`

<!DOCTYPE html><html><head><meta charset="UTF-8"><meta
name="viewport"
content="width=device-width, initial-scale=1.0">

<title>
Ultimate Admin Dashboard V4
</title><script src="https://cdn.jsdelivr.net/npm/chart.js"></script><style>

* {

box-sizing:
border-box;

font-family:
system-ui,
sans-serif;

}


body {

margin:
0;

padding:
15px;

background:
#0f172a;

color:
#e2e8f0;

}


.container {

max-width:
1450px;

margin:
auto;

}


.header {

display:
flex;

justify-content:
space-between;

align-items:
center;

gap:
12px;

flex-wrap:
wrap;

margin-bottom:
20px;

}


h1 {

margin:
0;

font-size:
24px;

color:
#38bdf8;

}


h2 {

color:
#38bdf8;

font-size:
17px;

}


.card {

background:
#1e293b;

padding:
15px;

border-radius:
12px;

margin-bottom:
15px;

overflow-x:
auto;

}


.stats {

display:
grid;

grid-template-columns:
repeat(
auto-fit,
minmax(150px,1fr)
);

gap:
10px;

margin-bottom:
15px;

}


.stat {

background:
#1e293b;

padding:
15px;

border-radius:
10px;

border:
1px solid
#334155;

}


.stat-title {

font-size:
11px;

color:
#94a3b8;

text-transform:
uppercase;

}


.stat-value {

font-size:
22px;

font-weight:
bold;

margin-top:
5px;

}


.filters {

display:
flex;

gap:
8px;

flex-wrap:
wrap;

align-items:
center;

}


.search,
select,
input[type=date],
.nickname-input {

padding:
9px;

border-radius:
6px;

border:
1px solid
#475569;

background:
#0f172a;

color:
white;

}


.search {

width:
240px;

}


.nickname-input {

width:
130px;

padding:
7px;

}


.btn {

border:
0;

border-radius:
6px;

padding:
9px 11px;

color:
white;

font-weight:
bold;

cursor:
pointer;

font-size:
11px;

text-decoration:
none;

display:
inline-block;

}


.refresh-btn {

background:
#3b82f6;

}


.logout-btn {

background:
#475569;

}


.approve {

background:
#16a34a;

}


.block {

background:
#ea580c;

}


.pending-btn {

background:
#ca8a04;

}


.delete-btn {

background:
#dc2626;

}


.badge {

display:
inline-block;

padding:
5px 8px;

border-radius:
5px;

font-size:
10px;

font-weight:
bold;

}


.approved,
.online {

background:
#14532d;

color:
#4ade80;

}


.pending {

background:
#78350f;

color:
#fbbf24;

}


.blocked {

background:
#7f1d1d;

color:
#f87171;

}


.offline {

background:
#334155;

color:
#cbd5e1;

}


table {

width:
100%;

border-collapse:
collapse;

min-width:
900px;

}


th,
td {

padding:
12px 10px;

border-bottom:
1px solid
#334155;

text-align:
left;

font-size:
13px;

}


th {

background:
#0f172a;

white-space:
nowrap;

}


.action-cell {

display:
flex;

gap:
6px;

flex-wrap:
wrap;

min-width:
220px;

}


code {

background:
#0f172a;

padding:
4px 7px;

border-radius:
4px;

color:
#94a3b8;

font-size:
11px;

word-break:
break-all;

}


small {

color:
#94a3b8;

}


.chart-card {

height:
370px;

}


.pagination {

display:
flex;

gap:
10px;

justify-content:
center;

align-items:
center;

margin-top:
15px;

}


.pagination button {

padding:
8px 12px;

border:
0;

border-radius:
6px;

background:
#334155;

color:
white;

cursor:
pointer;

}


.pagination button:disabled {

opacity:
.4;

cursor:
not-allowed;

}


@media(max-width:600px) {

body {

padding:
8px;

}

.search {

width:
100%;

}

}


</style></head><body><div class="container"><div class="header"><div><h1>
Ultimate Admin Dashboard V4
</h1><small
id="refreshStatus">

Loading dashboard...

</small></div><div
style="
display:flex;
gap:8px;
align-items:center;
"><button
onclick="refreshDashboard()"
class="btn refresh-btn">

Refresh

</button><form
method="POST"
action="/logout"
style="margin:0;"><input
type="hidden"
name="_csrf"
value="${escapeHtml(res.locals.csrfToken)}">

<button
class="btn logout-btn"
type="submit">

Logout

</button></form></div></div><div class="card"><form
class="filters"
id="filterForm"><input
class="search"
id="search"
name="search"
value="${escapeHtml(search)}"
placeholder="Search nickname or device ID...">

<select
id="filter"
name="filter">

<option
value="all"
${filter === "all" ? "selected" : ""}>All Time

</option><option
value="today"
${filter === "today" ? "selected" : ""}>Today (IST)

</option><option
value="7d"
${filter === "7d" ? "selected" : ""}>Last 7 Days

</option><option
value="30d"
${filter === "30d" ? "selected" : ""}>Last 30 Days

</option><option
value="custom"
${filter === "custom" ? "selected" : ""}>Custom Range

</option></select><input
type="date"
id="from"
name="from"
value="${escapeHtml(customFrom)}">

<input
type="date"
id="to"
name="to"
value="${escapeHtml(customTo)}">

<button
class="btn refresh-btn"
type="submit">

Apply

</button></form></div><div class="stats"><div class="stat"><div class="stat-title">
Total Devices
</div><div
class="stat-value"
id="totalDevices">- 

</div></div><div class="stat"><div class="stat-title">
Approved
</div><div
class="stat-value"
id="approved">- 

</div></div><div class="stat"><div class="stat-title">
Pending
</div><div
class="stat-value"
id="pending">- 

</div></div><div class="stat"><div class="stat-title">
Blocked
</div><div
class="stat-value"
id="blocked">- 

</div></div><div class="stat"><div class="stat-title">
Online Now
</div><div
class="stat-value"
id="online">- 

</div></div><div class="stat"><div class="stat-title">
Usage
</div><div
class="stat-value"
id="totalUsage">- 

</div></div></div><div
class="card chart-card"><h2>
Daily Usage Trend
</h2><div
style="height:290px;"><canvas
id="usageChart">

</canvas></div></div><div class="card"><h2>
Device Permission Manager
</h2><table><thead><tr><th>
Nickname
</th><th>
Device ID
</th><th>
Permission
</th><th>
Live
</th><th>
Usage
</th><th>
Registered
</th><th>
Actions
</th></tr></thead><tbody
id="deviceTable"><tr><td
colspan="7"
style="text-align:center;">Loading...

</td></tr></tbody></table><div
class="pagination"><button
id="prevPage">

Previous

</button><span
id="pageInfo">

Page -

</span><button
id="nextPage">

Next

</button></div></div></div><script>


const csrfToken =
"${escapeHtml(res.locals.csrfToken)}";


let currentPage =
${page};


let chartInstance =
null;


let refreshTimer =
null;


let isTyping =
false;


const refreshStatus =
document.getElementById(
"refreshStatus"
);


/* =====================================================
   HTML ESCAPE
===================================================== */

function escapeHTML(value) {

return String(
value ?? ""
)

.replace(
/&/g,
"&amp;"
)

.replace(
/</g,
"&lt;"
)

.replace(
/>/g,
"&gt;"
)

.replace(
/"/g,
"&quot;"
)

.replace(
/'/g,
"&#039;"
);

}


/* =====================================================
   LOAD DASHBOARD
===================================================== */

async function refreshDashboard() {

try {

refreshStatus.innerText =
"Refreshing...";


refreshStatus.style.color =
"#38bdf8";


const params =
new URLSearchParams();


params.set(

"search",

document
.getElementById("search")
.value

);


params.set(

"filter",

document
.getElementById("filter")
.value

);


params.set(

"from",

document
.getElementById("from")
.value

);


params.set(

"to",

document
.getElementById("to")
.value

);


params.set(

"page",

currentPage

);


const response =
await fetch(

"/api/dashboard?" +
params.toString(),

{

credentials:
"same-origin",

cache:
"no-store"

}

);


if (!response.ok) {

throw new Error(
"Dashboard request failed"
);

}


const data =
await response.json();


if (!data.success) {

throw new Error(
"Dashboard API error"
);

}


updateStats(
data.stats
);


updateChart(
data.chart
);


updateTable(
data.devices
);


updatePagination(
data.pagination
);


refreshStatus.innerText =
"Auto-refresh active";

refreshStatus.style.color =
"#4ade80";


scheduleRefresh();

}
catch (error) {

console.error(error);


refreshStatus.innerText =
"Refresh failed";

refreshStatus.style.color =
"#f87171";


scheduleRefresh();

}

}


/* =====================================================
   STATS
===================================================== */

function updateStats(stats) {

document
.getElementById("totalDevices")
.innerText =
stats.totalDevices;


document
.getElementById("approved")
.innerText =
stats.approved;


document
.getElementById("pending")
.innerText =
stats.pending;


document
.getElementById("blocked")
.innerText =
stats.blocked;


document
.getElementById("online")
.innerText =
stats.online;


document
.getElementById("totalUsage")
.innerText =
stats.totalUsage;

}


/* =====================================================
   CHART
===================================================== */

function updateChart(chart) {

const canvas =
document.getElementById(
"usageChart"
);


if (chartInstance) {

chartInstance.destroy();

}


chartInstance =
new Chart(
canvas,
{

type:
"line",

data:
{

labels:
chart.labels,

datasets:
[

{

label:
"Usage Minutes",

data:
chart.data,

borderWidth:
2,

tension:
0.3,

fill:
true,

borderColor:
"#38bdf8",

backgroundColor:
"rgba(56,189,248,.12)"

}

]

},

options:
{

responsive:
true,

maintainAspectRatio:
false,

plugins:
{

legend:
{

labels:
{

color:
"#e2e8f0"

}

}

},

scales:
{

x:
{

ticks:
{

color:
"#94a3b8"

},

grid:
{

color:
"#334155"

}

},

y:
{

beginAtZero:
true,

ticks:
{

color:
"#94a3b8"

},

grid:
{

color:
"#334155"

}

}

}

}

}

);

}


/* =====================================================
   TABLE
===================================================== */

function updateTable(devices) {

const tbody =
document.getElementById(
"deviceTable"
);


if (!devices.length) {

tbody.innerHTML =
\`

<tr>

<td
colspan="7"
style="
text-align:center;
padding:20px;
">

No devices found.

</td>

</tr>

\`;

return;

}


tbody.innerHTML =
devices.map(
(device) => {

const permission =
escapeHTML(
device.status
);


const liveClass =
device.online
?
"online"
:
"offline";


const liveText =
device.online
?
"ONLINE"
:
"OFFLINE";


return \`

<tr>


<td>


<form
method="POST"
action="/action/nickname"
style="
display:flex;
gap:5px;
">


<input
type="hidden"
name="_csrf"
value="\${csrfToken}">


<input
type="hidden"
name="deviceId"
value="\${escapeHTML(device.deviceId)}">


<input
class="nickname-input"
name="nickname"
value="\${escapeHTML(device.nickname)}"
placeholder="Nickname"
maxlength="50">


<button
class="btn refresh-btn"
type="submit">

Save

</button>


</form>


</td>


<td>

<code>
\${escapeHTML(device.deviceId)}
</code>

</td>


<td>

<span
class="badge \${permission}">

\${permission.toUpperCase()}

</span>

</td>


<td>

<span
class="badge \${liveClass}">

\${liveText}

</span>

</td>


<td>

<strong>
\${escapeHTML(device.usage)}
</strong>

<br>

<small>
\${device.sessions} sessions
</small>

</td>


<td>

\${escapeHTML(device.registeredAt)}

</td>


<td
class="action-cell">


\${

device.status !== "approved"

?

\`

<form
method="POST"
action="/action/approve">

<input
type="hidden"
name="_csrf"
value="\${csrfToken}">

<input
type="hidden"
name="deviceId"
value="\${escapeHTML(device.deviceId)}">

<button
class="btn approve"
type="submit">

Approve

</button>

</form>

\`

:

\`

<form
method="POST"
action="/action/block">

<input
type="hidden"
name="_csrf"
value="\${csrfToken}">

<input
type="hidden"
name="deviceId"
value="\${escapeHTML(device.deviceId)}">

<button
class="btn block"
type="submit">

Block

</button>

</form>

\`

}


\${

device.status !== "pending"

?

\`

<form
method="POST"
action="/action/pending">

<input
type="hidden"
name="_csrf"
value="\${csrfToken}">

<input
type="hidden"
name="deviceId"
value="\${escapeHTML(device.deviceId)}">

<button
class="btn pending-btn"
type="submit">

Pending

</button>

</form>

\`

:

""

}


<form
method="POST"
action="/action/delete"
onsubmit="
return confirm(
'Delete this device permanently?'
);
">


<input
type="hidden"
name="_csrf"
value="\${csrfToken}">


<input
type="hidden"
name="deviceId"
value="\${escapeHTML(device.deviceId)}">


<button
class="btn delete-btn"
type="submit">

Delete

</button>


</form>


</td>


</tr>

\`;

}

).join("");

}


/* =====================================================
   PAGINATION
===================================================== */

function updatePagination(pagination) {

currentPage =
pagination.page;


document
.getElementById("pageInfo")
.innerText =
"Page " +
pagination.page +
" of " +
pagination.totalPages;


document
.getElementById("prevPage")
.disabled =
pagination.page <= 1;


document
.getElementById("nextPage")
.disabled =
pagination.page >=
pagination.totalPages;

}


/* =====================================================
   AUTO REFRESH
===================================================== */

function scheduleRefresh() {

clearTimeout(
refreshTimer
);


if (isTyping) {

refreshStatus.innerText =
"Refresh paused while typing";

refreshStatus.style.color =
"#fbbf24";

return;

}


refreshTimer =
setTimeout(

() => {

refreshDashboard();

},

${DASHBOARD_REFRESH_SECONDS * 1000}

);

}


document
.querySelectorAll(
"input, select"
)
.forEach(
(element) => {

element.addEventListener(
"focus",
() => {

isTyping =
true;


clearTimeout(
refreshTimer
);


refreshStatus.innerText =
"Refresh paused while typing";


refreshStatus.style.color =
"#fbbf24";

}
);


element.addEventListener(
"blur",
() => {

isTyping =
false;


scheduleRefresh();

}
);

}
);


/* =====================================================
   FILTER FORM
===================================================== */

document
.getElementById(
"filterForm"
)
.addEventListener(
"submit",
(event) => {

event.preventDefault();


currentPage =
1;


refreshDashboard();

}
);


document
.getElementById(
"filter"
)
.addEventListener(
"change",
() => {

currentPage =
1;

}
);


/* =====================================================
   PAGINATION EVENTS
===================================================== */

document
.getElementById(
"prevPage"
)
.addEventListener(
"click",
() => {

if (
currentPage > 1
) {

currentPage--;

refreshDashboard();

}

}
);


document
.getElementById(
"nextPage"
)
.addEventListener(
"click",
() => {

currentPage++;

refreshDashboard();

}
);


/* =====================================================
   INITIAL LOAD
===================================================== */

refreshDashboard();


</script></body></html>    `);

}

);

/* =========================================================
SERVER START
========================================================= */

app.listen(
PORT,
() => {

    console.log(
        "Ultimate Admin Dashboard V4 running on port " +
        PORT
    );

}

);
