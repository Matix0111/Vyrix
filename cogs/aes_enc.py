import discord
import os
import base64
from discord.ext import commands

class AESCommands(commands.Cog):
    def __init__(self, client):
        self.client = client
    
    async def generate(self, context, command):
        encode = context.message.content.endswith('base64')
        I_E = False
        try:
            key_size = command[2]
        except IndexError:
            I_E = True

        if key_size == 'base64':
            key_size = 256

        bit_convert = {
            128: 16,
            192: 24,
            256: 32
        }

        if key_size not in bit_convert.keys():
            await context.message.channel.send('Invalid key size.')
        else:
            if encode:
                await context.message.channel.send(base64.b64encode(os.urandom(bit_convert[key_size])).decode())
            else:
                await context.message.channel.send(os.urandom(bit_convert[key_size]))

    @commands.command()
    async def aes(self, context):
        actions = {
            'encrypt': 0,
            'decrypt': 1,
            'generate': self.generate,
        }
        command = context.message.content.split(' ')
        if command[1] not in actions.keys():
            await context.message.channel.send(f'Unrecognized command {command[1]}')
        else:
            await actions[command[1]](context, command)

    @commands.Cog.listener()
    async def on_ready(self):
        print('AES cog loaded')

def setup(client):
    client.add_cog(AESCommands(client))