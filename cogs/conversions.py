import discord
from discord.ext import commands

class Conversions(commands.Cog):
    def __init__(self, client):
        self.client = client
    
    @commands.Cog.listener()
    async def on_ready(self):
        print('Conversions cog loaded')
    
    @commands.command()
    async def by2bi(self, context):
        byteValue = context.message.content.split(' ')[1]
        bitValue = int(byteValue)*8
        await context.message.channel.send(f'{byteValue} bytes = {bitValue} bits (bytes*8)')

    @commands.command()
    async def bi2by(self, context):
        bitValue = context.message.content.split(' ')[1]
        byteValue = int(bitValue)/8
        await context.message.channel.send(f'{bitValue} bits = {byteValue} bytes (bits/8)')

def setup(client):
    client.add_cog(Conversions(client))
