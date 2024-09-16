import { Hono } from 'hono'
import type { FC } from 'hono/jsx'
import { zValidator } from '@hono/zod-validator'
import { z} from 'zod'
import { generateId, Lucia } from "lucia";
import { D1Adapter } from "@lucia-auth/adapter-sqlite";

import type { User, Session } from "lucia";
import { csrf } from 'hono/csrf';
import { getCookie } from 'hono/cookie';
import {Scrypt} from "lucia"

import { TimeSpan, createDate, isWithinExpirationDate } from "oslo";
import { generateRandomString, alphabet } from "oslo/crypto";
import { Resend } from 'resend';

export type Env = {
  RESEND_API_KEY : string;
}

async function generateEmailVerificationCode(
  db: D1Database, userId: string, email: string)
  : Promise<string> {
  
  await db.prepare('delete from email_verification_codes where user_id = ?').
        bind(userId).run();

	const code = generateRandomString(8, alphabet("0-9"));

  await db.prepare('insert into email_verification_codes (user_id, email, code, expires_at) values (?,?,?,?)').
  bind(userId,email, code, createDate(new TimeSpan(15, "m")).toString()).run()
	return code;
}


export function initializeLucia(D1: D1Database) {
	const adapter = new D1Adapter(D1, {
		user: "users",
		session: "sessions"
	});
	return new Lucia(adapter, {
    sessionCookie: {
      attributes: {
        secure: false
      }
    },
    getUserAttributes: (attributes) => {
      return {
        email: attributes.email,
        emailVerified: Boolean(attributes.email_verified),
       
      };
    }
  });
}

const sendVerificationEmail = async (
  env:Bidings,
  recipient: string,
  subject: string,
  verificationCode: string,
)=>{

  const resend = new Resend(env.RESEND_API_KEY);

  const { data, error } = await resend.emails.send({
    from: "verification@e-ayala.com",
    to: recipient,
    subject: subject,
    html: `<p> Your verification code is: ${verificationCode}</p>`,
  });
}


interface DatabaseUserAttributes {
	email: string;
  email_verified: number;
}


declare module "lucia" {
	interface Register {
		Lucia: ReturnType<typeof initializeLucia>;
    DatabaseUserAttributes: DatabaseUserAttributes;
	}
}

type UserRow = {
  id: string;
  email: string;
  hashed_password: string;
  email_verified:number
}


type Bidings = {
  DB: D1Database
  RESEND_API_KEY:string
}


type EmailVerificationCode = {
  id: number;
  code: string;
  email: string;
  expires_at : string;
}

const app = new Hono<{
  Bindings: Bidings
	Variables: {
		user: User | null;
		session: Session | null;
	};
}>();

app.use(csrf());

app.use("*", async (c, next) => {
  const lucia = initializeLucia(c.env.DB)
	const sessionId = getCookie(c, lucia.sessionCookieName) ?? null;
	if (!sessionId) {
		c.set("user", null);
		c.set("session", null);
		return next();
	}
	const { session, user } = await lucia.validateSession(sessionId);
	if (session && session.fresh) {
		// use `header()` instead of `setCookie()` to avoid TS errors
		c.header("Set-Cookie", lucia.createSessionCookie(session.id).serialize(), {
			append: true
		});
	}
	if (!session) {
		c.header("Set-Cookie", lucia.createBlankSessionCookie().serialize(), {
			append: true
		});
	}
	c.set("user", user);
	c.set("session", session);
	return next();
});


const Layout: FC = (props) => {
  return (
    <html>
      <body>{props.children}</body>
    </html>
  )
}


app.get('/', (c) => {
  const user = c.get("user")

  if(user){
    return c.html(
      <Layout>
      {user.emailVerified ? <div>Current user: {JSON.stringify(user)}</div>
      : <form method='post' action= "/email-verification"> <input name="code"/> <button>verify</button></form> }
    
    <br />

    <form method='post' action='/logout'>
      <button>Logout</button>
    </form>
      </Layout>
    )
  }
  return c.html(<Layout>
    <a href='/signup'>signup</a>
    <br />
    <a href="/login">login</a>
  </Layout>)
})


app.get('/signup', (c) =>{
  return c.html(
    <Layout>
    <br/>
      <form method = "post">
      <label for="email"><b>Email</b></label>
        <input type="text" name= "email"  required/>
        <label for="psw"><b>Password</b></label>
        <input  type="password" name= "password" required/>

        <button>Signup</button>

      </form>
    </Layout>
  )
})


app.post('/signup',
  zValidator("form", 
    z.object({
      email: z.string().email(),
      password: z.string().min(6).max(20),
    })
  ),
   async (c) =>{
    const  {email, password} = c.req.valid('form');
    const lucia = initializeLucia(c.env.DB)

    const passwordHash = await  new Scrypt().hash(password);
    const userId = generateId(10); 
  
    try {
      const insertedUser = await c.env.DB
        .prepare('insert into users (id,email,hashed_password,email_verified) values (?,?,?,?) returning *')
        .bind(userId,email,passwordHash, false)
        .first();
        console.log(insertedUser)

        const verificationCode = await generateEmailVerificationCode(c.env.DB,userId, email);

        console.log(verificationCode)

        await sendVerificationEmail(
          c.env,
          email,
          "Welcome",
          verificationCode
        );
	      
  
        const session = await lucia.createSession(userId, {});
        const sessionCookie = lucia.createSessionCookie(session.id);
        c.header("Set-Cookie", sessionCookie.serialize(), {
          append:true
      })
      return c.redirect("/")
    } catch (err) {
      // db error, email taken, etc
      console.log(err)
      return c.body("Something went wrong!!", 400)

    }
})


app.post('/login',
  zValidator("form", 
    z.object({
      email: z.string().email(),
      password: z.string().min(6).max(20),
    })
  ),
   async (c) =>{
    const  {email, password} = c.req.valid('form');
    const lucia = initializeLucia(c.env.DB)


    const user = await c.env.DB.prepare('select * from users where email = ?')
      .bind(email)
      .first<UserRow>();

      if(!user){
        return c.body("Invalid email or password", 400)
      }
      const validPasword = await new Scrypt().verify(user.hashed_password, password)
      if(!validPasword){
        return c.body("invalid password", 400)
      }

      const session = await lucia.createSession(user.id, {});
      const sessionCookie = lucia.createSessionCookie(session.id);
      c.header("Set-Cookie", sessionCookie.serialize(), {
        append:true
      })
      return c.redirect("/")
    
})



app.get('/login', (c) =>{
  return c.html(
    <Layout>
    <br/>
      <form method = "post">
        <input name= "email" />
        <input  type="password" name= "password"/>

        <button>Login</button>

      </form>
    </Layout>
  )
})



app.post("/logout", async (c) =>{
  const lucia = initializeLucia(c.env.DB);
  const session = c.get("session")

  if(session){
    await lucia.invalidateSession(session.id)
  }
  const sessionCookie = lucia.createBlankSessionCookie();
  c.header("Set-Cookie", sessionCookie.serialize(), {
    append:true
  })
  return c.redirect("/")
})


async function verifyVerificationCode(db: D1Database,  user: User, code: string){

  const databaseCode = await db.prepare('delete from email_verification_codes where user_id = ? and code = ? and email = ? returning *').
    bind(user.id,code, user.email).
    first<EmailVerificationCode>();

	if (!databaseCode ) {
		return false;
	}

	if (!isWithinExpirationDate( new Date(databaseCode.expires_at))) {
		return false;
	}

	// if (databaseCode.email !== user.email) {
	// 	return false;
	// }
	return true;
}


app.post ("/email-verification",
  zValidator(
    "form",
    z.object({
      code: z.string().min(6)
    })  
  ), 
  async (c) => {
    const user  = c.get("user");
    const  {code} = c.req.valid("form");

    if(!user){
      return c.body(null,404)
    }

    const validCode = await verifyVerificationCode(c.env.DB, user, code)
    if(!validCode){
      return c.body(null,400)
    }

    const lucia = initializeLucia(c.env.DB)
    await lucia.invalidateUserSessions(user.id);
    await c.env.DB.prepare('update users set email_verified = ? where id = ?').
          bind(true, user.id)
          .run();

    const session = await lucia.createSession(user.id, {});
    const sessionCookie = lucia.createSessionCookie(session.id);
    c.header("Set-Cookie", sessionCookie.serialize(), {
        append:true
      })
    return c.redirect("/")
    

})


export default app
