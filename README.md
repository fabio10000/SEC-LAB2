## How to run
### Client
Just execute `cargo run` and everything should work.

### Server
Before executing the server you have to create a .env file a configure the values related to the smtp server.
The easiest way to achieve that is to create a copy of `.env.example` ex: `cp .env.example .env` and replace with your own settings.
For test purposes I recommend to use a service like [mailtrap](https://mailtrap.io) to avoid using your personnal email address. 

Once the `.env` file ready just execute `cargo run` and everything should work fine