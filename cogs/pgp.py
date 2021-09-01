import discord
from discord.ext import commands
import gnupg

Local_gpg = gnupg.GPG(keyring='/root/.gnupg/pubring.gpg')
VYRIX_KEY = Local_gpg.export_keys('VYRIX')
# print(VYRIX_KEY)
Vyrix_gpg = gnupg.GPG(homedir='cogs/KEYRING', keyring='cogs/KEYRING')

class PGPCommands(commands.Cog):
    def __init__(self, client):
        self.client = client
    
    @commands.command()
    async def get_key(self, context):
        VYRIX_key_embed = discord.Embed(title='Vyrix PGP Key')
        VYRIX_key_embed.add_field(name='Algorithm: ED25519', value=VYRIX_KEY)
        await context.message.channel.send(embed=VYRIX_key_embed)

    @commands.Cog.listener()
    async def on_ready(self):
        print('PGP cog loaded')

def setup(client):
    client.add_cog(PGPCommands(client))