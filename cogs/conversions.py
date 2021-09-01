import discord
import requests
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

    @commands.command()
    async def f2c(self, context):
        f = context.message.content.split(' ')[1]
        is_valid = True
        try:
            f = float(f)
        except ValueError:
            await context.message.channel.send('Please enter a number.')
            is_valid = False
        
        if is_valid:
            c = (float(f) - 32) * 5/9
            await context.message.channel.send(f"{f}F = {c:.2f}C")

    @commands.command()
    async def c2f(self, context):
        c = context.message.content.split(' ')[1]
        is_valid = True
        try:
            c = float(c)
        except ValueError:
            await context.message.channel.send('Please enter a number.')
            is_valid = False
        
        if is_valid:
            f = (float(c) * 9/5) + 32
            await context.message.channel.send(f"{c}C = {f:.2f}F")

    @commands.command()
    async def usd2btc(self, context):
        usd = context.message.content.split(' ')[1]
        current_btc = requests.get('https://api.coindesk.com/v1/bpi/currentprice/USD.json').json()
        current_btc = current_btc['bpi']['USD']['rate_float']
        converted = f'{int(usd)/current_btc:.6f}'
        await context.message.channel.send(f'${usd} USD = {converted:,} bitcoin')

    @commands.command()
    async def btc2usd(self, context):
        btc = context.message.content.split(' ')[1]
        current_btc = requests.get('https://api.coindesk.com/v1/bpi/currentprice/USD.json').json()
        current_btc = current_btc['bpi']['USD']['rate_float']
        converted = f'{float(btc)*current_btc:.6f}'
        await context.message.channel.send(f'{btc} bitcoin = ${converted:,} USD')

def setup(client):
    client.add_cog(Conversions(client))
