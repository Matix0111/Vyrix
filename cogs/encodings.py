import discord
import base64 as b64
import binascii
import io
import hashlib
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
    
    def extract_file_extension(self, filename):
        split_filename = filename.split(".")[1:]
        return "." + '.'.join(split_filename)

    @commands.command()
    async def encode(self, context):
        cmdSplit = context.message.content.split(' ')
        algo = cmdSplit[1]
        if algo in encoders.keys():
            if len(context.message.attachments) > 0:
                attachment_content = await context.message.attachments[0].read()
                filename = context.message.attachments[0].filename
                file_ext = self.extract_file_extension(filename)
                digest = hashlib.md5(str(attachment_content).encode()).hexdigest()
                filename = digest + file_ext
                encoded_attachment = encoders[algo](attachment_content).decode()
                obj = io.BytesIO(encoded_attachment.encode())
                file = discord.File(fp=obj, filename=filename)
                await context.message.channel.send(file=file)
            else:
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
            if len(context.message.attachments) > 0:
                attachment_content = await context.message.attachments[0].read()
                filename = context.message.attachments[0].filename
                file_ext = self.extract_file_extension(filename)
                digest = hashlib.md5(str(attachment_content).encode()).hexdigest()
                filename = digest + file_ext
                decoded_attachment = decoders[algo](attachment_content).decode()
                obj = io.BytesIO(decoded_attachment.encode())
                file = discord.File(fp=obj, filename=filename)
                await context.message.channel.send(file=file)
            else:
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