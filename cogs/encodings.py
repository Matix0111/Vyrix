import discord
import tempfile
import base64 as b64
import binascii
import tempfile
from discord.ext import commands

decoders = {
    'base85': b64.b85decode,
    'base64': b64.b64decode,
    'base32': b64.b32decode,
    'base16': b64.b16decode,
    'ascii85': b64.a85decode,
    'hex': binascii.a2b_hex
}

encoders = {
    'base85': b64.b85encode,
    'base64': b64.b64encode,
    'base32': b64.b32encode,
    'base16': b64.b16encode,
    'ascii85': b64.a85encode,
    'hex': binascii.b2a_hex
}

class Encoders(commands.Cog):
    def __init__(self, client):
        self.client = client

    @commands.command()
    async def encode(self, context):
        cmdSplit = context.message.content.split(' ')
        algo = cmdSplit[1]
        if algo in encoders.keys():
            original = ' '.join(cmdSplit[2:])
            encoded = encoders[algo](original.encode()).decode()
            encoderEmbed = discord.Embed(title='Encoder')
            encoderEmbed.add_field(name='Algorithm: ', value=algo)
            encoderEmbed.add_field(name='Original: ', value=original)
            encoderEmbed.add_field(name='Encoded: ', value=f'```{encoded.strip()}```')
            await context.message.channel.send(embed=encoderEmbed)
    
    @commands.command()
    async def decode(self, context):
        cmdSplit = context.message.content.split(' ')
        algo = cmdSplit[1]
        if algo in decoders.keys():
            encoded = ' '.join(cmdSplit[2:])
            original = decoders[algo](encoded.encode()).decode()
            encoderEmbed = discord.Embed(title='Decoder')
            encoderEmbed.add_field(name='Algorithm: ', value=algo)
            encoderEmbed.add_field(name='Encoded: ', value=f'```{encoded.strip()}```')
            encoderEmbed.add_field(name='Decoded: ', value=f'{original}')
            await context.message.channel.send(embed=encoderEmbed)

    @commands.Cog.listener()
    async def on_ready(self):
        print('Encodings cog loaded')

def setup(client):
    client.add_cog(Encoders(client))