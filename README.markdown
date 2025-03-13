# roleguard

a hyperspecific(?) discord bot

Admins can use `/addguard` or `/removeguard` to allow/disallow a specified user to set a password for a specified role. Then allowed users can use `/setpassword` to set a password for that role. Finally, anybody can use `/unlock` with the right password to get the bot to give them that role. The unusual goal is that admins and even the bot owner don't know the password (unless they actively tamper with the bot's code).

## on choosing passwords

For the specific use case of guarding a puzzlehunt spoiler channel:

The simplest and easiest-to-understand thing to do would be to set the password to the final metapuzzle's answer or something similar. The password does not undergo any puzzlehunt-style normalization, so you should also specify how to format it, e.g. "all caps no spaces".

One downside is that then people can then use the bot for (arbitrarily many) extra answer guesses. If you want to avoid that, or if this scheme doesn't work for any other reason, you could say that the password is something else that only teams who finish have access to, e.g. "the first sentence in the body of the victory page".

## permissions

According to my notes, the bot needs these permissions:

- Manage Roles
- Read Messages
- Send Messages
- Use Application Commands (Slash Commands)

## TODO

- `/listguards`
- If desired, set multiple passwords per role? (I did this at first but decided to keep it simple)
- Reasonable password-removing command
- I'm probably logging too much if I want others to use this

## license

Blue Oak Model License 1.0.0, because
