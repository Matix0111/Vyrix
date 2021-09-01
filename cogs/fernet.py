import discord
from discord.ext import commands
from cryptography.fernet import *
import sqlite3

con = sqlite3.connect('encKeys.db')
cur = con.cursor()

def checkForTable():
    cur.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='keys'")
    if cur.fetchone()[0] == 1:
        return True
    else:
        cur.execute('''CREATE TABLE keys (userid text, key text, multikey integer, other_keys text)''')
        con.commit()
        print('Table now exists')
        return False

class fernetCommands(commands.Cog):
    def __init__(self, client):
            self.client = client

    def fetchKey(self, user):
        cur.execute('SELECT key FROM keys WHERE userid=?', (f"{user}",))

        try:
            return cur.fetchone()[0]
        except TypeError:
            return 'failed'

    def createAndAdd(self, user, k):
        cur.execute(f"INSERT INTO keys VALUES (?, ?, ?, ?)", (f"{user}", f"{k}", 0, ""))
        con.commit()

    def updateKey(self, user, mode, keyamount):
        if mode == 'm':
            newKeys = self.generateKeys(keyamount)
            cur.execute(f"UPDATE keys SET key = (?) WHERE userid = (?)", (newKeys, user))
            con.commit()

        else:
            newKey = Fernet.generate_key()
            cur.execute(f"UPDATE keys SET key = (?) WHERE userid = (?)", (newKey.decode(), user))
            con.commit()
            return newKey

    def deleteKey(self, user):
        cur.execute("DELETE FROM keys WHERE userid = (?)", (user,))
        con.commit()
    
    '''
        User section
    '''

    def retrieveKeys(self, user):
        cur.execute("SELECT other_keys FROM keys WHERE userid = (?)", (user,))
        return cur.fetchone()[0]

    def importKey(self, key, user):
        currentKeys = self.retrieveKeys(user)
        arr = [currentKeys, key]
        newValue = ' '.join(arr)
        cur.execute(f"UPDATE keys SET other_keys = (?) WHERE userid = (?)", (newValue, user))
        con.commit()
    
    def clearKeys(self, user):
        cur.execute(f"UPDATE keys SET other_keys = (?) WHERE userid = (?)", ("", user))
        con.commit()
    
    @commands.command()
    async def gen_shared(self, context):
        usr = context.message.author.id
        sharedKey = Fernet.generate_key().decode()
        self.importKey(sharedKey, usr)
        keys = self.retrieveKeys(usr).split(' ')
        index = keys.index(sharedKey)
        await context.message.author.send(f'Your generated shareable key is {sharedKey} and the ID is {index-1}')

    @commands.command()
    async def import_key(self, context):
        keyToImport = context.message.content.split(' ')[1]
        self.importKey(keyToImport, context.message.author.id)
        await context.message.author.send('Key successfully imported!')
    
    @commands.command()
    async def list_keys(self, context):
        keys = self.retrieveKeys(context.message.author.id).split(' ')[1:]
        try:
            if len(keys) <= 0:
                await context.message.channel.send("You have no keys.")
            else:
                keysEmbed = discord.Embed(title='Imported keys')
                for iter, key in enumerate(keys):
                    keysEmbed.add_field(name=f'{[iter]} : ', value=f'{key}', inline=False)
                await context.message.author.send(embed=keysEmbed)
        except discord.errors.HTTPException:
            await context.message.channel.send("You have no keys.")
    
    @commands.command()
    async def clear_keys(self, context):
        self.clearKeys(context.message.author.id)
        await context.message.channel.send("Imported keys cleared...")
    
    @commands.command()
    async def encrypt_with(self, context):
        usr = context.message.author.id
        cmd = context.message.content.split(' ')

        messageToEncrypt = ' '.join(cmd[2:]).encode()
        keyToUse = int(cmd[1])

        key = self.retrieveKeys(usr).split(' ')[int(keyToUse)+1].encode()
        f = Fernet(key)
        token = f.encrypt(messageToEncrypt)
        Embed = discord.Embed(title='Encryption')
        Embed.add_field(name='Encrypted message: ', value=token.decode())

        await context.message.channel.send(embed=Embed)
    
    @commands.command()
    async def decrypt_with(self, context):
        usr = context.message.author.id
        cmd = context.message.content.split(' ')

        messageToDencrypt = ' '.join(cmd[2:]).encode()
        keyToUse = int(cmd[1])

        key = self.retrieveKeys(usr).split(' ')[int(keyToUse)+1].encode()
        f = Fernet(key)
        token = f.decrypt(messageToDencrypt)

        Embed = discord.Embed(title='Decrypt')
        Embed.add_field(name='Decrypted message: ', value=token.decode())

        await context.message.channel.send(embed=Embed)
    
    '''
        Multikey section
    '''

    def checkForMultikey(self, user):
        cur.execute(f"SELECT multikey FROM keys WHERE userid=?", (f"{user}",))
        return cur.fetchone()
    
    def generateKeys(self, keyAmount):
        _keys = []
        for _ in range(keyAmount):
            _keys.append(Fernet.generate_key().decode())
        return ' '.join(_keys)
    
    def changeMultikey(self, user, state, keyAmount=5):
        if state == 'e':
            newKeys = self.generateKeys(keyAmount)
            cur.execute(f"UPDATE keys SET multikey = (?) WHERE userid = (?)", (1, user))
            con.commit()
            cur.execute(f"UPDATE keys SET key = (?) WHERE userid = (?)", (newKeys, user))
            con.commit()
        else:
            newKey = Fernet.generate_key().decode()
            cur.execute(f"UPDATE keys SET multikey = (?) WHERE userid = (?)", (0, user))
            con.commit()
            cur.execute(f"UPDATE keys SET key = (?) WHERE userid = (?)", (newKey, user))
            con.commit()
            return newKey
    
    def retrieveMultikey(self, authorID):
        keys = self.fetchKey(authorID).split(' ')
        byteKeys = [Fernet(x.encode()) for x in keys]
        f = MultiFernet(byteKeys)
        return f

    @commands.command()
    async def enable_multikey(self, context):
        author = str(context.message.author)
        authorid = str(context.message.author.id)
        if self.checkForMultikey(authorid) == (0,):
            self.changeMultikey(authorid, 'e')
            print(f'User {author} has enabled multikey.')
            await context.message.channel.send('Multikey enabled!')
            keys = self.fetchKey(authorid).split(' ')
            keyEmbed = discord.Embed(title='Fernet keys: ')
            for keynum, key in enumerate(keys, 1):
                keyEmbed.add_field(name=f'Key {keynum}: ', value=f'`{key}`', inline=False)
            
            await context.message.author.send(embed=keyEmbed)
        else:
            await context.message.channel.send(f'You already have multikey enabled.')
    
    @commands.command()
    async def disable_multikey(self, context):
        author = str(context.message.author)
        authorid = str(context.message.author.id)
        if self.checkForMultikey(authorid) == (1,):
            nk = self.changeMultikey(authorid, 'd')
            print(f'User {author} has disabled multikey.\nKey: {nk}')
            await context.message.channel.send('Multikey disabled!')
            await context.message.author.send(f'Your new key is: `{nk}`')
        else:
            await context.message.channel.send(f'You do not have mutlikey enabled.')

    @commands.command()
    async def rotate_msg(self, context):
        authorID = str(context.message.author.id)
        if self.checkForMultikey(authorID) == (1,):
            f = self.retrieveMultikey(authorID)
            msg = (context.message.content.split(' ')[1]).encode()
            _failed = False
            try:
                f1 = f.rotate(msg)
            except InvalidToken:
                await context.message.channel.send('This encrypted message was not encrypted using a multifernet key.')
                _failed = True
            
            if not _failed:
                Embed = discord.Embed(title='Rotate')
                Embed.add_field(name='Rotated message: ', value=f1.decode())
                await context.message.channel.send(embed=Embed)
            else:
                pass
        else:
            await context.message.channel.send('You do not have multikey enabled.')
    
    @commands.command()
    async def check_multi(self, context):
        if self.checkForMultikey(str(context.message.author.id)) == (1,):
            await context.message.channel.send('You have multikey enabled.')
        else:
            await context.message.channel.send('You have multikey disabled.')
    
    @commands.command()
    async def key_override(self, context):
        usr = context.message.author.id
        if self.checkForMultikey(usr) == (1,):
            _overrideAmount = context.message.content.split(' ')[1]
            error = False
            try:
                _overrideAmount = int(_overrideAmount)
            except ValueError:
                await context.message.channel.send('Override amount must be an integer.')
                error = True

            if not error:
                if _overrideAmount > 10 or _overrideAmount < 3:
                    await context.message.channel.send('Override amount must be between 3-10')
                else:
                    self.changeMultikey(usr, 'e', _overrideAmount)
                    await context.message.channel.send(f'Keys in MultiFernet rotation overridden to {_overrideAmount}')
        else:
            await context.message.channel.send('You do not have multikey enabled.')

    @commands.command()
    async def rotation(self, context):
        if self.checkForMultikey(context.message.author.id) == (1,):
            keyAmount = len(self.fetchKey(context.message.author.id).split(' '))
            await context.message.channel.send(f'Keys in your MultiFernet rotation: {keyAmount}')
        else:
            await context.message.channel.send(f'You do not have a MultiFernet key.')

    '''
        REST
    '''

    @commands.command()
    async def my_key(self, context):
        author = str(context.message.author.id)
        if self.checkForMultikey(author) == (1,):
            keys = self.fetchKey(author).split(' ')
            keyEmbed = discord.Embed(title='Fernet keys: ')
            for keynum, key in enumerate(keys, 1):
                keyEmbed.add_field(name=f'Key {keynum}: ', value=f'`{key}`', inline=False)
            
            await context.message.author.send(embed=keyEmbed)
        else:
            key = self.fetchKey(author)
            if key == 'Failed':
                await context.message.channel.send('You have no registered Fernet keys.')
            else:
                await context.message.author.send(f'Your Fernet encryption key is: `{key}`')

    @commands.command()
    async def gen_key(self, context):
        author = str(context.message.author.id)
        check = self.fetchKey(author)
        authorS = context.message.author
        if check != 'Failed':
            await context.message.channel.send('User already exists.')
        else:
            key = Fernet.generate_key()
            self.createAndAdd(author, key.decode())
            print(f'User {authorS} created key {key.decode()}')
            embed = discord.Embed(title='Encryption')
            embed.add_field(name=f'Fernet key for {authorS}', value='Successfully created', inline=False)
            await context.message.channel.send(embed=embed)

    @commands.command()
    async def regen_key(self, context):
        authorid = str(context.message.author.id)
        if self.checkForMultikey(authorid) == (1,):
            amountOfKeys = len(self.fetchKey(authorid).split(' '))
            self.updateKey(authorid, 'm', amountOfKeys)
            await context.message.channel.send(f'MultiFernet rotation of {amountOfKeys} successfully changed.')
        else:
            authorKey = self.fetchKey(authorid)
            if authorKey == 'Failed':
                await context.message.channel.send('You have no key.')
            else:
                newKey = self.updateKey(authorid, 's', 1)
                print(f'{context.message.author} regenerated their fernet key! {authorKey} -> {newKey.decode()}')
                await context.message.channel.send('Fernet key successfully changed.')

    @commands.command()
    async def del_key(self, context):
        authorid = str(context.message.author.id)
        self.deleteKey(authorid)
        print(f'user {context.message.author} deleted their fernet key!')
        await context.message.channel.send('Fernet key successfully deleted.')

    @commands.command()
    async def encrypt(self, context):
        authorID = str(context.message.author.id)
        messageToEncrypt = ' '.join(context.message.content.split(' ')[1:])
        if self.checkForMultikey(authorID) == (1,):
            f = self.retrieveMultikey(authorID)
            token = f.encrypt(messageToEncrypt.encode())
            Embed = discord.Embed(title='Encryption | **!MULTIKEY ENABLED!**')
            Embed.add_field(name='Encrypted message: ', value=token.decode())

            await context.message.channel.send(embed=Embed)

        else:
            if len(messageToEncrypt) <= 0:
                await context.message.channel.send('Please specify a message to encrypt.')
            else:
                key = self.fetchKey(authorID)
                if key == 'Failed':
                    await context.message.channel.send('You do not have a key registered. Register one with ./gen_key')
                else:
                    f = Fernet(key)
                    token = f.encrypt(messageToEncrypt.encode())
                    Embed = discord.Embed(title='Encryption')
                    Embed.add_field(name='Encrypted message: ', value=token.decode())
                    await context.message.channel.send(embed=Embed)

    @commands.command()
    async def decrypt(self, context):
        authorID = str(context.message.author.id)
        messageToDencrypt = ''.join(context.message.content.split(' ')[1:])
        if self.checkForMultikey(authorID) == (1,):
            f = self.retrieveMultikey(authorID)
            token = f.decrypt(messageToDencrypt.encode())
            Embed = discord.Embed(title='Decryption')
            Embed.add_field(name='Encrypted message: ', value=token.decode())
            await context.message.channel.send(embed=Embed)
        else:
            key = self.fetchKey(authorID)
            if key == 'Failed':
                await context.message.channel.send('You do not have a key registered. Register one with ./gen_key')
            else:
                f = Fernet(key)
                token = f.decrypt(messageToDencrypt.encode())
                Embed = discord.Embed(title='Decryption')
                Embed.add_field(name='Encrypted message: ', value=token.decode())
                await context.message.channel.send(embed=Embed)
    
    @commands.Cog.listener()
    async def on_ready(self):
        print('Fernet cog loaded')

def setup(client):
    client.add_cog(fernetCommands(client))