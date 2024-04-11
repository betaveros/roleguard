import base64
import dataclasses
import hashlib
import json
import logging
import os
import secrets
from collections import defaultdict
from typing import Any, Callable, Coroutine, Iterable, TypeVar

import discord
import discord.ext

from config import GUILD_IDS, TOKEN

discord.utils.setup_logging()

intents = discord.Intents.default()
client = discord.Client(intents=intents)
tree = discord.app_commands.CommandTree(client)
guilds = [discord.Object(id=gid) for gid in GUILD_IDS]

# It's fine to declare commands without specifying the guild but apparently "it will take up to an hour to register the command if it's for all guilds"


class Failed(Exception):
    "Trivial exception representing a message we want to reply to the user with"

    def __init__(self, msg: str):
        self.msg = msg


@client.event
async def on_ready():
    if guilds:
        for guild in guilds:
            logging.info(f"Syncing with {guild=}")
            await tree.sync(guild=guild)
    load()
    logging.info("Ready")


def og_scrypt(password: bytes, salt: bytes) -> bytes:
    # OG old-ish params for interactive login c. 2009, but good enough
    return hashlib.scrypt(
        password,
        salt=salt,
        n=2**14,
        r=8,
        p=1,
    )


def password_hash(password: str) -> tuple[bytes, bytes]:
    b = password.encode("utf-8")
    if len(b) > 1024:
        raise Failed(f"Password too long, 1024 bytes or less please")
    salt = os.urandom(16)
    return (salt, og_scrypt(b, salt))


def check_password_hash(password: str, salted_hash: tuple[bytes, bytes]):
    b = password.encode("utf-8")
    if len(b) > 1024:
        raise Failed(f"Password must be 1024 bytes or less (got {len(b)} bytes)")
    salt, pw_hash = salted_hash
    if not secrets.compare_digest(pw_hash, og_scrypt(b, salt)):
        raise Failed("Wrong password")


T = TypeVar("T")


def assert_not_none(x: T | None) -> T:
    assert x is not None
    return x


@dataclasses.dataclass
class GuildState:
    # Keyed by member id rather than member so we can deserialize without
    # needing the Discord member intent or one API call per member.
    guards: dict[int, set[discord.Role]] = dataclasses.field(
        default_factory=lambda: defaultdict(set)
    )
    password_hashes: dict[discord.Role, tuple[bytes, bytes]] = dataclasses.field(
        default_factory=dict
    )

    def serialize(self):
        return (
            {
                member: [role.id for role in roles]
                for member, roles in self.guards.items()
            },
            {
                role.id: [
                    base64.b64encode(salt).decode("ascii"),
                    base64.b64encode(pw).decode("ascii"),
                ]
                for role, (salt, pw) in self.password_hashes.items()
            },
        )

    @classmethod
    def deserialize(cls, guild_id: int, obj):
        guild = assert_not_none(client.get_guild(guild_id))
        guards_obj, pws_obj = obj
        return cls(
            guards=defaultdict(
                set,
                {
                    int(member_id): {
                        assert_not_none(guild.get_role(int(role_id)))
                        for role_id in role_ids
                    }
                    for member_id, role_ids in guards_obj.items()
                },
            ),
            password_hashes={
                assert_not_none(guild.get_role(int(role_id))): (
                    base64.b64decode(salt.encode("ascii")),
                    base64.b64decode(pw.encode("ascii")),
                )
                for role_id, (salt, pw) in pws_obj.items()
            },
        )


state = defaultdict(GuildState)


def get_guild_state(interaction: discord.Interaction) -> GuildState:
    if not interaction.guild_id:
        raise Failed("Need to interact in a server")
    return state[interaction.guild_id]


def save():
    with open("state.json", "w") as outfile:
        json.dump({gid: gstate.serialize() for gid, gstate in state.items()}, outfile)


def load():
    try:
        with open("state.json", "r") as infile:
            global state
            state = {
                int(guild_id): GuildState.deserialize(int(guild_id), value)
                for guild_id, value in json.load(infile).items()
            }
            logging.info(f"Loaded state for {len(state)} guild(s)")
    except FileNotFoundError:
        logging.info("No state found")
        pass


@tree.command(
    description="Add guard (user who can set the password for some role)", guilds=guilds
)
@discord.app_commands.checks.has_permissions(administrator=True)
async def addguard(
    interaction: discord.Interaction, member: discord.Member, role: discord.Role
):
    try:
        guild_state = get_guild_state(interaction)
        if not role.is_assignable():
            raise Failed(f"I don't have the permissions to assign {role}!")
        guild_state.guards[member.id].add(role)
        save()
        logging.info(f"{member} is now guarding {role}")
        await interaction.response.send_message(
            f"{member} is now guarding {role}", ephemeral=True
        )
    except Failed as e:
        logging.warning(f"{interaction.user}: {e.msg}")
        await interaction.response.send_message(e.msg, ephemeral=True)


@tree.command(
    description="Remove guard (user who can set the password for some role)",
    guilds=guilds,
)
@discord.app_commands.checks.has_permissions(administrator=True)
async def removeguard(
    interaction: discord.Interaction, member: discord.Member, role: discord.Role
):
    try:
        guild_state = get_guild_state(interaction)
        try:
            guild_state.guards[member.id].remove(role)
        except KeyError:
            raise Failed(f"{member} was not guarding {role.name}")
        save()
        logging.info(f"{member} removed from guarding {role}")
        await interaction.response.send_message(
            f"{member} removed from guarding {role}", ephemeral=True
        )
    except Failed as e:
        logging.warning(f"{interaction.user}: {e.msg}")
        await interaction.response.send_message(e.msg, ephemeral=True)


def to_member_or_fail(user: discord.User | discord.Member) -> discord.Member:
    if not isinstance(user, discord.Member):
        # not certain this is the right error
        raise Failed("This bot only works inside specific Discord servers, not in PMs")
    return user


@tree.command(
    description="Set password for some role (or type DISABLE to disable it)",
    guilds=guilds,
)
async def setpassword(interaction: discord.Interaction):
    try:
        member = to_member_or_fail(interaction.user)
        guild_state = get_guild_state(interaction)
        guarded_roles = guild_state.guards[member.id]
        if not guarded_roles:
            raise Failed(f"You aren't allowed to set the password for any roles")

        v = discord.ui.View()
        v.add_item(
            LimitedRoleSelect(
                "Set password for", list(guarded_roles), setpassword_handler
            )
        )
        await interaction.response.send_message(
            "Select role to set password for", view=v, ephemeral=True
        )
    except Failed as e:
        logging.warning(f"{interaction.user}: {e.msg}")
        await interaction.response.send_message(e.msg, ephemeral=True)


async def setpassword_handler(
    interaction: discord.Interaction, role: discord.Role, password: str
):
    try:
        member = to_member_or_fail(interaction.user)
        guild_state = get_guild_state(interaction)
        guarded_roles = guild_state.guards[member.id]
        if role not in guarded_roles:
            s = ", ".join(r.name for r in guarded_roles)
            raise Failed(
                f"You aren't allowed to set the password for {role.name} (only {s})"
            )
        if password == "DISABLE":
            pw_hash = None
            guild_state.password_hashes.pop(role, None)
        else:
            pw_hash = password_hash(password)
            guild_state.password_hashes[role] = pw_hash
        save()
        logging.info(f"{interaction.user} set password for {role} to {pw_hash}")
        if pw_hash:
            await interaction.response.send_message(
                f"Set password for {role.name}",
                ephemeral=True,
            )
        else:
            await interaction.response.send_message(
                f"Disabled password for {role.name}", ephemeral=True
            )
    except Failed as e:
        logging.warning(f"{interaction.user}: {e.msg}")
        await interaction.response.send_message(e.msg, ephemeral=True)


@tree.command(description="Unlock some role with password", guilds=guilds)
async def unlock(interaction: discord.Interaction):
    try:
        guild_state = get_guild_state(interaction)
        if not guild_state.password_hashes:
            raise Failed(f"No passwords have been enabled for any roles on this server")

        v = discord.ui.View()
        v.add_item(
            LimitedRoleSelect(
                "Enter password to unlock",
                list(guild_state.password_hashes),
                unlock_handler,
            )
        )
        await interaction.response.send_message(
            "Select role to unlock", view=v, ephemeral=True
        )
    except Failed as e:
        logging.warning(f"{interaction.user}: {e.msg}")
        await interaction.response.send_message(e.msg, ephemeral=True)


async def unlock_handler(
    interaction: discord.Interaction, role: discord.Role, password: str
):
    try:
        guild_state = get_guild_state(interaction)
        member = to_member_or_fail(interaction.user)
        if role not in guild_state.password_hashes:
            raise Failed("This role has no passwords, you can't unlock it")
        check_password_hash(password, guild_state.password_hashes[role])
        try:
            await member.add_roles(role, reason=f"Unlocked {role.name} with password")
        except (discord.Forbidden, discord.HTTPException) as e:
            raise Failed(f"Password accepted, but couldn't add role: {e}")
        logging.info(f"Granted {role} to {member}")
        await interaction.response.send_message(
            f"Role {role.name} granted!", ephemeral=True
        )
    except Failed as e:
        logging.warning(f"{interaction.user}: {e.msg}")
        await interaction.response.send_message(e.msg, ephemeral=True)


# For reasons I don't understand, it looks like Discord allows all UI elements
# other than text boxes in bot message responses, and *only* text boxes in
# modals. But we want one dropdown and one textbox, hence this awkward
# two-phase thing. (We could also just make users specify the role and password
# inline when issuing the command, but I am tentatively concerned this flow
# makes it easy to accidentally send the password to a channel, or will at
# least cause users to worry more about that)
class LimitedRoleSelect(discord.ui.Select):
    def __init__(
        self,
        title_prefix: str,
        roles: list[discord.Role],
        handler: Callable[
            [discord.Interaction, discord.Role, str], Coroutine[Any, Any, None]
        ],
    ):
        options = [
            discord.SelectOption(label=role.name, value=str(i))
            for i, role in enumerate(roles)
        ]
        super().__init__(
            placeholder="Select role", min_values=1, max_values=1, options=options
        )
        self.title_prefix = title_prefix
        self.roles = list(roles)
        self.handler = handler

    async def callback(self, interaction: discord.Interaction):
        title = f"{self.title_prefix} {self.roles[int(self.values[0])].name}"
        if len(title) > 45:
            title = title[:42] + "…"
        await interaction.response.send_modal(
            PasswordModal(title, self.roles[int(self.values[0])], self.handler)
        )


class PasswordModal(discord.ui.Modal):
    password = discord.ui.TextInput(label="Password")

    def __init__(self, title, role, handler):
        super().__init__(title=title)
        self.role = role
        self.handler = handler

    async def on_submit(self, interaction: discord.Interaction):
        await self.handler(interaction, self.role, str(self.password))


client.run(TOKEN)
