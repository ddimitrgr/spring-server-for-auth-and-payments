## Spring server for authentication and payments
Authentication and user management server using mongodb for storage. Provides the following functionality:

- User registration with email verirification
- JWT token based authentication
- User phone verification and store. Uses Twilio.
- Product subscription (*) management and payments. Uses Stripe.

(*) There is automatic subscription renewal: the user subscription ends only when subscription
is explicitly cancelled and the last date of subscription is before the current date.

## Usage
In application.properties set parameter values for the following:
- mongodb connection
- SMTP parameters for sending registration/password reset emails
- Stripe API key
- Twilio API key
- Email templates
- Domain of front-end to setup a CORS domain
- Expiration for JWT, session (**) and email verification

(**) A session is created for all anonymous users (currently unused).

## Deployment
Package to produce a ROOT.war in target/ and deploy eg in AWS EBS directly from that directory:
```bash
mvn package
cd target
eb init -i --profile <profile>
eb create <env-name> --profile <profile>
```
