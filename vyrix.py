import base64 as b64
import configparser
import argparse
import datetime
import hashlib
import hmac
import json
import os
import random
import re
import signal
import logging
import secrets
import statistics
import string
import uuid
import shutil
import atexit
import sys
import asyncio
import argon2

from cryptography.fernet import Fernet, InvalidToken
import bcrypt
from getpass import getpass

from discord.enums import ActivityType
from cogs.fernet import checkForTable
from cogs.games import checkForGamesTable
from cogs.encodings import encoders
from collections import Counter

import discord
import requests
from discord.ext import commands

ph = argon2.PasswordHasher()

parser = argparse.ArgumentParser()
parser.add_argument('-v', '--verbose', action='store_true', help='Activate error verbosity.')
parser.add_argument('-l', '--log', action='store_true', help='Log chat activity.')
args = parser.parse_args()

formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(name)s | %(message)s')

loggerHandler = logging.StreamHandler()
loggerHandler.setFormatter(formatter)

failedLogger = logging.getLogger('!COMMAND FAILURE!')
failedLogger.setLevel(logging.INFO)
failedLogger.addHandler(loggerHandler)

chatLogger = logging.getLogger('CHAT LOG')
chatLogger.setLevel(logging.INFO)
chatLogger.addHandler(loggerHandler)

successLogger = logging.getLogger('COMMAND COMPLETION')
successLogger.setLevel(logging.INFO)
successLogger.addHandler(loggerHandler)

commandRegex = re.compile(r'\./\w+')
nwordRegex = re.compile(r"(n|i){1,32}((g{1,32}|q){1,32}|[gq]{1,32})[e3ra]{1,32}")

intents = discord.Intents.all()
client = commands.Bot(command_prefix='./', intents = intents)

client.remove_command('help')

with open('bot-sources/commands.json', 'r') as readfile:
    commandsJSON = json.load(readfile)
    print('Commands JSON file loaded...')

cmdsAmount = 0

for i in commandsJSON['Commands']:
    cmds = commandsJSON['Commands'][i]
    for key in cmds:
        keys = key.keys()
        cmdsAmount += len(keys)

with open('bot-sources/sayings.json', 'r') as readfile:
    complimentsJSON = json.load(readfile)
    sayings = complimentsJSON['sayings']
    print('Compliments JSON file loaded...')

conf = configparser.ConfigParser()
conf.read('/opt/MB/auth.ini')

def handler(signum, frame):
    print('\nSignal handler called with signal', signum)
    exit()

signal.signal(signal.SIGALRM, handler)

@atexit.register
def cleanup():
    shutil.rmtree('cogs/__pycache__')
    print('Cache cleared..')

def unlockInformation():
    os.system('clear')
    signal.alarm(5) # Set 5s timeout
    try:
        password = getpass().encode()
    except KeyboardInterrupt:
        print('\nExitting...')
        exit()
    
    signal.alarm(0) # Reset timeout

    salt = conf['UNLOCK']['salt'].encode()
    kdf = bcrypt.kdf(
        password=password,
        salt=salt,
        desired_key_bytes=32,
        rounds=50
    )

    return kdf

key = b64.urlsafe_b64encode(unlockInformation())

f = Fernet(key)

try:
    token = f.decrypt(conf['AUTH']['token'].encode()).decode()
    ipinfoToken = f.decrypt(conf['AUTH']['ipinfoToken'].encode()).decode()
    weatherToken = f.decrypt(conf['AUTH']['weatherToken'].encode()).decode()
    e6Key = f.decrypt(conf['AUTH']['e6Key'].encode()).decode()
    rapidAPIKey = f.decrypt(conf['AUTH']['x-rapidapi-key'].encode()).decode()
    whAPI = f.decrypt(conf['AUTH']['wallhavenapi'].encode()).decode()
except InvalidToken:
    print('[!] AUTHENTICATION FAILURE...')
    exit()

print('Password accepted.')

headersE6 = {'user-agent': 'e621-post-grabber-MultiBot (by Matix on e621)'}
headersWAPI = {
    'x-rapidapi-key': rapidAPIKey,
    'x-rapidapi-host': 'wordsapiv1.p.rapidapi.com'
}

e6colour = 0x00549e
redColour = 0xfc0105
rooColour = 0x88deff

encKey = """
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEYJ80pxYJKwYBBAHaRw8BAQdAR59KT8VtGVvZ2cJzPdGnJlVK/9FPBXakoHw9
9FNkCZK0BVZZUklYiJYEExYIAD4WIQTKXSCmVD2OaR1jT//PjQEu62PmQgUCYJ80
pwIbAwUJAChIWQULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRDPjQEu62PmQm/c
AQC0h6LPT/TPSA1bT+q9AFedLRkUrOQt4RmonhaZo68fdgD9FOUHOnzEugMWz6AV
bg8pzykwggOsJ8IR6CrT6PSEDgC4OARgnzSnEgorBgEEAZdVAQUBAQdAs+JA+9MU
Ba5b/u6AXGlimttZ0wCoE4PW2b96xYzCqiIDAQgHiH4EGBYIACYWIQTKXSCmVD2O
aR1jT//PjQEu62PmQgUCYJ80pwIbDAUJAChIWQAKCRDPjQEu62PmQtUDAP9f8UNH
WfpcadlGiSmcoyHnAnWuI/m5U9DGfsswUFA+PAEA9kkNtBOFvCoGrN0fdPb3TYxu
q+rQNAbddPgLIJx7vgE=
=QMl9
-----END PGP PUBLIC KEY BLOCK-----
"""

badWords = ['nigger', 'nigga', 'fag', 'faggot', 'kys']

general_channel = client.get_channel(701881058164998216)
welcome_channel = client.get_channel(802705006276378665)
botStatusChannel = client.get_channel(802706944933625876)

@client.command(name='info', pass_context=True)
async def info(context):
    infoEmbed = discord.Embed(title='Vyrix Information')
    infoEmbed.set_thumbnail(url='https://media.vyrix.xyz/apx08ftp/vyrix/VYRIX.png')
    infoEmbed.add_field(name='Developer: ', value='Matix Protopuppy', inline=False)
    infoEmbed.add_field(name='Official Vyrix Website: ', value='https://vyrix.xyz', inline=False)
    infoEmbed.add_field(name='Command count: ', value=f'{cmdsAmount}', inline=True)
    await context.message.channel.send(embed=infoEmbed)

@client.command(name="shred")
@commands.has_permissions(manage_messages=True)
async def shred(context, limit=None):
    if limit != None:
        error = False
        try:
            limit = int(limit)
        except ValueError:
            await context.message.channel.send('Limit must be a number.')
            error = True
        
        if error:
            pass
        else:
            if limit <= 0:
                await context.message.channel.send('Limit must be 1 or more.')
            else:
                await context.message.channel.purge(limit=(int(limit)+1))

@client.command(name='user_count', pass_context = True)
async def memberCount(context):
    guild = context.message.author.guild
    totalusercount = guild.member_count
    membercount = len([m for m in guild.members if not m.bot])
    msg = f"""
User count: {str(membercount)}
Bot count: {str(totalusercount - membercount)}
    """
    await context.message.channel.send(msg)
    
    # users = []
    # async for member in guild.fetch_members(limit=150):
    #     users.append(member.name)
    # embed_ = discord.Embed(title='Users:')
    # for i in range(len(users)):
    #     embed_.add_field(name=f'Member {i}: ', value=users[i], inline=False)
    # await context.message.channel.send(embed=embed_)

@client.command(name='kick', pass_context = True)
@commands.has_permissions(kick_members = True)
async def kick(context, member: commands.MemberConverter=None):
    reason = ' '.join(context.message.content.split(' ')[2:])
    if context.message.author == member:
        await context.message.channel.send("You can't kick yourself.")
    elif member == None:
        await context.message.channel.send("Specify a user.")
    else:
        txt = f'You have been kicked from {context.message.guild}'
        if reason == None:
            pass
        else:
            txt += f" for reason : {reason}"
        await member.send(txt)
        memberName = member.display_name
        await member.kick(reason=reason)
        try:
            await context.message.channel.send('User ' + memberName + ' has been kicked for "' + reason + '"')
        except TypeError:
            await context.message.channel.send('User ' + memberName + ' has been kicked')

@client.command(name='ban', pass_context = True)
@commands.has_permissions(kick_members = True, ban_members = True)
async def ban(context, member: commands.MemberConverter=None, *, reason=None):
    if context.message.author == member:
        await context.message.channel.send("You can't ban yourself.")
    elif member == None:
        await context.message.channel.send("Specify a user.")
    else:
        txt = f'You have been banned from {context.message.guild}'
        if reason == None:
            pass
        else:
            txt += f" for reason : {reason}"
        await member.send(txt)
        memberName = member.display_name
        await member.ban(reason=reason)
        await context.message.channel.send('User ' + memberName + ' has been banned for "' + reason + '"')

@client.command(name='avatar', pass_context = True)
async def avatar(context, member: commands.MemberConverter=None):
    if member is None:
        user = context.message.author
        url = user.avatar_url
        await context.message.channel.send(url)
    else:
        url = member.avatar_url
        await context.message.channel.send(url)

@client.command(name='change_nick', pass_context = True)
@commands.has_permissions(change_nickname=True, manage_nicknames=True)
async def change_nick(context, member: commands.MemberConverter, nickname=None):
    currentNick = member.nick
    newNick = nickname
    if newNick == None:
        await context.message.channel.send("Operation aborted.")
    else:
        await member.edit(nick=newNick)
        nicknameEditEmbed = discord.Embed(title='Nickname Update')
        nicknameEditEmbed.add_field(name='Affected user: ', value=str(member))
        nicknameEditEmbed.add_field(name='Changes:', value=f'{currentNick} to {newNick}', inline=False)
        await context.message.channel.send(embed=nicknameEditEmbed)

@client.command(name='whois', pass_context = True)
async def whois(context, member: commands.MemberConverter):
    if member is None:
        await context.message.channel.send('Please specify a member.')
    else:
        userProf = member.public_flags
        userEmbed = discord.Embed(title='whois')
        for i, j in userProf:
            userEmbed.add_field(name=i, value=j, inline=False)
        await context.message.channel.send(embed=userEmbed)

@client.command(name="roles", pass_context = True)
async def roles(context):
    guild = context.message.author.guild

    #await context.message.channel.send(_roles)
    roles = []
    rolesRaw = await guild.fetch_roles()
    for i in range(len(rolesRaw)):
        roles.append(rolesRaw[i])
    del roles[0]
    embed_ = discord.Embed(title='Roles:')
    for i in range(len(roles)):
        embed_.add_field(name=f'Role {i}: ', value=roles[i], inline=False)
    await context.message.channel.send(embed=embed_)

@client.command(name="random_choice", pass_context = True)
async def randomChoice(context):
    messageContent = context.message.content[16::]
    choicesGiven = messageContent.split("-")
    chosenValue = secrets.choice(choicesGiven)
    await context.message.channel.send('Random value: ' + chosenValue)

@client.command(name="cute_check", pass_context = True)
async def cuteCheck(context, member: commands.MemberConverter):
    cute = secrets.randbelow(100)
    await context.message.channel.send(f'{member.name} is {cute}% cute.')

@client.command(name='dm_member', pass_context = True)
@commands.has_permissions(manage_guild = True)
async def dmMember(context, member: commands.MemberConverter=None, message=None):
    # recpID = context.message.content[12:30]
    if member == None:
        await context.message.channel.send('Please specify a user.')
    elif member == None and message != None:
        # member = discord.Guild.get_member(recpID)
        await member.send(content=message)
    elif message == None:
        await context.message.channel.send('Please specify a message.')
    else:
         await member.send(content=message)

@client.command(name='ip_lookup', pass_context = True)
async def ipLookup(context, ip=None):
    if ip == None:
        await context.message.channel.send('Please specify an IP.')
    else:
        response = requests.get(f'http://ipinfo.io/{ip}/json?token={ipinfoToken}')
        if response.status_code == 404:
            await context.message.channel.send('404 recieved! Make sure the IP is a valid IP address.')
        else:
            response = response.json()
            response = response.items()
            ipEmbed = discord.Embed(title='IP Information.', colour=0xbe110c)
            for key, value in response:
                ipEmbed.add_field(name=f'{key} : ', value=f'{value}')
            await context.message.channel.send(embed=ipEmbed)

@client.command(name="post", pass_context = True)
async def post(context, postID=None):
    senderMsg = context.message
    _is_artist = False
    if postID == None:
        await context.message.channel.send('Please make sure you specify a post ID!')
    elif postID == 'random':
        rq = requests.get(f'https://e621.net/posts/random.json?', headers=headersE6, auth=('Matix', f'{e6Key}'))
    elif str(postID).isdigit():
        rq = requests.get(f'https://e621.net/posts/{postID}.json', headers=headersE6, auth=('Matix', f'{e6Key}'))
    else:
        postID = postID.replace(':', '%3A')
        rq = requests.get(f'https://e621.net/posts.json?tags={postID}+order%3Arandom+limit%3A1', headers=headersE6, auth=('Matix', f'{e6Key}'))
        _is_artist = True
    
    if rq.status_code == 200:
        rqJSON = rq.json()

        blacklisted_tags = [
            "gore",
            "scat",
            "watersports",
            "fart",
            "fart_fetish",
            "fart_cloud",
            "vore",
            "diaper",
            "peeing"
        ]

        if _is_artist:
            url = rqJSON['posts'][0]['file']['url']
            md5sum = rqJSON['posts'][0]['file']['md5']
            post = rqJSON['posts'][0]['sample']['url']
            tags = rqJSON['posts'][0]['tags']['general']
            postid = rqJSON['posts'][0]['id']
            artist = rqJSON['posts'][0]['tags']['artist']
            rating = rqJSON['posts'][0]['rating']
        else:
            url = rqJSON['post']['file']['url']
            md5sum = rqJSON['post']['file']['md5']
            post = rqJSON['post']['sample']['url']
            tags = rqJSON['post']['tags']['general']
            postid = rqJSON['post']['id']
            artist = rqJSON['post']['tags']['artist']
            rating = rqJSON['post']['rating']
        
        if "cub" in tags or "young" in tags:
            await senderMsg.delete()
            cubEmbed = discord.Embed(title='Command termination.', colour=redColour)
            cubEmbed.add_field(name='Post contains cub tag.', value='Cub is a prohibited tag, this cannot be overridden.')
            await context.message.channel.send(embed=cubEmbed)
        elif any(x in tags for x in blacklisted_tags):
            await senderMsg.delete()
            cubEmbed = discord.Embed(title='Command termination.', colour=redColour)
            cubEmbed.add_field(name='Post contains a blacklisted tag.', value='Default blacklist cannot be overridden.')
            await context.message.channel.send(embed=cubEmbed)
        else:
            keyerror = False

            try:
                if _is_artist:
                    score = rqJSON['posts'][0]['score']['total']
                else:
                    score = rqJSON['post']['score']['total']
            except KeyError:
                keyerror = True
            
            if keyerror:
                await context.message.channel.send('Invalid ID!')

            if len(artist) > 1:
                artist = ", ".join(artist)
            elif len(artist) == 1:
                artist = artist[0]
            else:
                artist = 'Not specified.'

            if url == None:
                await context.message.channel.send('This post was deleted from e6.')
            else:
                open_content = f'Open content ({url.split(".")[-1].upper()})'

                if rating == 'e' and (context.channel.is_nsfw()) == False:
                    await context.message.channel.send('Explicit images are not allowed here.')
                    
                elif rating == 'e' and (context.channel.is_nsfw()) == True:
                    postEmbed = discord.Embed(title=f'{open_content}', url=f'{url}', colour = e6colour)
                    postEmbed.add_field(name='Post stats: ', value=f'e621 | Post: {postid} | Score: {score} | Artist(s): {artist}', inline=False)
                    postEmbed = postEmbed.set_image(url=post)

                elif rating == 's':
                    postEmbed = discord.Embed(title=f'{open_content}', url=f'{url}', colour = e6colour)
                    postEmbed.add_field(name='Post stats: ', value=f'e621 | Post: {postid} | Score: {score} | Artist(s): {artist}', inline=False)
                    postEmbed = postEmbed.set_image(url=post)

                postEmbed.set_footer(text=f'MD5sum: {md5sum}')

                try:
                    await context.message.channel.send(embed=postEmbed)
                except discord.errors.HTTPException:
                    await context.message.channel.send("400 Bad Request!")
    
    else:
        await context.message.channel.send(f'Status code {rq.status_code} recieved!')

@client.command(name="md5_to_post", pass_context = True)
async def md5ToPost(context, md5Hash=None):
    if md5Hash != None:
        md5Hash = context.message.content[14::]

        rq = requests.get(f'https://e621.net/posts.json?tags=md5%3A{md5Hash}', headers=headersE6, auth=('Matix', f'{e6Key}'))
        if rq.status_code == 403:
            await context.message.channel.send('403 Forbidden')
        else:
            rqJSON = rq.json()

            postID = rqJSON['posts'][0]['id']

            await context.message.channel.send(f'POST ID: {postID}')
            postEmbed = discord.Embed(title='Click here for the post. (On e621).', url=f'https://e621.net/posts/{postID}', colour = e6colour)
            await context.message.channel.send(embed=postEmbed)

@client.command(name='mct', pass_context = True)
async def MCT(context, numbers=None):
    numbers = context.message.content[6::]
    if numbers == None:
        print('Specify numbers, separated by dashes (-).')
    else:
        numbers = str(numbers).split('-')
        numbersOrder = sorted(zip(numbers))

        mean = 0
        for i in numbers:
            try:
                mean += int(i)
            except ValueError:
                continue

        mean = (mean/(len(numbers)))
        mode = Counter(numbers)
        mode = mode.most_common(1)[0]
        try:
            median = statistics.median(numbers)
        except TypeError:
            median = "NONE"

        MCTEmbed = discord.Embed(title='MCT', colour=0x00ff00)
        MCTEmbed.add_field(name='Mean: ', value=mean, inline=False)
        MCTEmbed.add_field(name='Median: ', value=median, inline=False)
        MCTEmbed.add_field(name='Mode: ', value=mode, inline=False)
        await context.message.channel.send(embed=MCTEmbed)

@client.command(name='req_key', pass_context = True)
async def reqKey(context):
    keyEmbed = discord.Embed(title='PGP Key')
    keyEmbed.add_field(name='KEY: ', value=f'{encKey}', inline=False)
    await context.message.author.send(embed=keyEmbed)

@client.command(name='gen_passwd', pass_context = True)
async def genPasswd(context):
    err = False
    try:
        length = int(context.message.content[13:])
    except ValueError:
        await context.message.channel.send('Specify a length!')
        err = True

    if err:
        pass
    else:
        alphabet = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        passwdEmbed = discord.Embed(title='Password Generator')
        passwdEmbed.add_field(name='Password: ', value=f'```{str(password)}```', inline=False)
        await context.message.channel.send(embed=passwdEmbed)

algos = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha224': hashlib.sha224,
    'sha256': hashlib.sha256,
    'sha384': hashlib.sha384,
    'sha512': hashlib.sha512,
    'argon2id': ph.hash,
    'bcrypt': bcrypt.hashpw
}

@client.command(name='hash', pass_context=True)
async def hasher(context):
    cmdSplit = context.message.content.split(' ')
    _error = False
    try:
        algo = cmdSplit[1].lower()
    except IndexError:
        await context.message.channel.send(f'Please select a supported algorithm: {", ".join(list(algos.keys()))}')
        _error = True
    
    if not _error:
        if algo in algos.keys():
            hashEmbed = discord.Embed(title='Hasher')
            hashEmbed.add_field(name='Algorithm: ', value=algo)
            message = cmdSplit[2:]
            
            if len(message) > 0:
                message = " ".join(message)
                if algo == 'bcrypt':
                    salt = bcrypt.gensalt()
                    _hash = algos[algo](str(message).encode(), salt).decode()
                    hashEmbed.add_field(name='Bcrypt salt: ', value=salt.decode(), inline=False)
                else:
                    _hash = algos[algo](str(message).encode())

                if algo != 'argon2id' and algo != 'bcrypt':
                    _hash = _hash.hexdigest()

                hashEmbed.add_field(name='Original data: ', value = message, inline=False)
                hashEmbed.add_field(name='Hash: ', value=_hash, inline=False)
                await context.message.channel.send(embed=hashEmbed)
            else:
                await context.message.channel.send('Please enter a message to hash.')
        else:
            await context.message.channel.send(f'Invalid algorithm! Supported algorithms: {", ".join(list(algos.keys()))}')

@client.command(name='salt', pass_context=True)
async def gensalt(context, rounds=12):
    print(rounds)
    if rounds >= 4 and rounds < 32:
        await context.message.channel.send(bcrypt.gensalt(rounds).decode())
    elif rounds < 4 or rounds > 31:
        await context.message.channel.send('Invalid rounds. Must be between 4 and 31.')

@client.command(name='hmac', pass_context=True)
async def HMAC(context, algorithm=None, key=None, data=None):
    if key == None:
        await context.message.channel.send('Usage: ./hmac "hashing algorithm" "hmac key" "data to hash"')
    elif data == None:
        await context.message.channel.send('Usage: ./hmac "hashing algorithm" "hmac key" "data to hash"')
    elif algorithm not in list(algos.keys()) or algorithm is None:
        await context.message.channel.send('Usage: ./hmac "hashing algorithm" "hmac key" "data to hash"')
    else:
        _extra = True

        if key == "$RNDKEY":
            key = secrets.token_urlsafe(16)
            _extra = False

        hmacHash = hmac.new(key.encode(), data.encode(), algos[algorithm.lower()]).hexdigest()
        hmacEmbed = discord.Embed(title='HMAC')
        hmacEmbed.add_field(name='Hashing algorithm: ', value=algorithm)
        hmacEmbed.add_field(name='HMAC key: ', value=key)
        hmacEmbed.add_field(name='HMAC data: ', value=data)
        hmacEmbed.add_field(name='HMAC hash: ', value=hmacHash)
        if _extra:
            hmacEmbed.add_field(name="Can't think of a key to use?", value='Replace the key field with $RNDKEY (keep the quotes)', inline=False)
        
        await context.message.channel.send(embed=hmacEmbed)

# @client.command(name='hmac-sha256', pass_context=True)
# async def hmacsha256(context, key=None, data=None):
#     digest = hmac.new(key.encode(), data.encode(), hashlib.sha256).hexdigest()
#     await context.message.channel.send(digest)

# @client.command(name='hmac-sha512', pass_context=True)
# async def hmacsha512(context, key=None, data=None):
#     digest = hmac.new(key.encode(), data.encode(), hashlib.sha512).hexdigest()
#     await context.message.channel.send(digest)

identifiers = {
    'md5': 32,
    'sha1': 40,
    'sha224': 56,
    'sha256': 64,
    'sha384': 96,
    'sha512': 128,
}

@client.command(name='identify', pass_context=True)
async def identify(context):
    _hash = context.message.content.split(' ')[1]
    if len(_hash) in identifiers.values():
        await context.message.channel.send(f'Hash is believed to be {list(identifiers.keys())[list(identifiers.values()).index(len(_hash))]}')
    else:
        await context.message.channel.send('Could not find hash type.')

@client.command(name='update_cstatus', pass_context=True)
async def updateCStatus(context):
    if context.message.author.id == 358029842048090113:
        original_status = client.guilds[0].get_member(client.user.id).status
        status = context.message.content[17:]
        if status == 'reset':
            await client.change_presence(status=discord.Status.do_not_disturb, activity=discord.Game('Living in Spain without the a'))
            await context.message.channel.send('Status successfully reset')
        else:
            await client.change_presence(status=original_status, activity=discord.Game(str(status)))
    else:
        await context.message.channel.send('no')

@client.command(name='update_ostatus', pass_context=True)
async def updateOStatus(context):
    if context.message.author.id == 358029842048090113:
        original_status = client.guilds[0].get_member(client.user.id).activity
        status = context.message.content[17:]
        if status == 'dnd':
            await client.change_presence(status=discord.Status.do_not_disturb, activity=original_status)
        elif status == 'idle':
            await client.change_presence(status=discord.Status.idle, activity=original_status)
        elif status == 'off':
            await client.change_presence(status=discord.Status.invisible, activity=original_status)
        elif status == 'on':
            await client.change_presence(status=discord.Status.online, activity=original_status)
    else:
        await context.message.channel.send('no')

def scram(content):
    contentL = list(content)
    random.shuffle(contentL)
    content = ''.join(contentL)
    return content

@client.command(name='scramble', pass_context=True)
async def scramble(context):
    ctn = context.message.content[11:]
    newMsg = scram(ctn)
    scramEmbed = discord.Embed(title='Scrambler', colour=redColour)
    scramEmbed.add_field(name='Original : ', value=ctn)
    scramEmbed.add_field(name='Scrambled : ', value=newMsg)
    await context.message.channel.send(embed=scramEmbed)

@client.command(name='urandom', pass_context=True)
async def osurandom(context, length):
    error = False
    _bytes = context.message.content[10:]
    try:
        _bytes = int(_bytes)
    except ValueError:
        await context.message.channel.send('Cannot use this value!')
        error = True

    if _bytes <= 0 or _bytes > 5000:
        await context.message.channel.send('Number must be between 1 and 5000.')
        error = True

    if error:
        pass
    else:
        rndval = int.from_bytes(os.urandom(_bytes), byteorder='big')
        if len(str(rndval)) >= 2000:
            await context.message.channel.send(f'Number exceeds 2000 characters by {len(str(rndval))-2000} characters')
        else:
            await context.message.channel.send(f'Number: {rndval}')

@client.command(name='uuid4', pass_context=True)
async def uuid4Addr(context):
    await context.message.channel.send(f'{uuid.uuid4()}')

@client.command(name='define', pass_context=True)
async def define(context):
    query = (context.message.content).split(' ')[1]
    urlBase = f'https://wordsapiv1.p.rapidapi.com/words/{query}/definition'
    responseJSON = requests.get(urlBase, headers=headersWAPI).json()
    definition = responseJSON['definition']
    definitionFound = True
    if len(definition) < 1:
        await context.message.channel.send('No definition found.')
        definitionFound = False
    
    if not definitionFound:
        pass
    else:
        definitionEmbed = discord.Embed(title='Definitions')
        if len(definition) > 1:
            j = 1
            for i in definition:
                definitionEmbed.add_field(name=f'Definition {j}:', value=i)
                j += 1
        else:
            definitionEmbed.add_field(name='Definition: ', value=definition[0])
        
        await context.message.channel.send(embed=definitionEmbed)

@client.command(name='synonyms', pass_context = True)
async def synonyms(context):
    query = (context.message.content).split(' ')[1]
    urlBase = f'https://wordsapiv1.p.rapidapi.com/words/{query}/synonyms'
    responseJSON = requests.get(urlBase, headers=headersWAPI).json()
    synonyms = responseJSON['synonyms']
    synonymsFound = True
    if len(synonyms) < 1:
        await context.message.channel.send('No Synonyms found.')
        synonymsFound = False
    
    if not synonymsFound:
        pass
    else:
        synonymsEmbed = discord.Embed(title='Synonyms')
        if len(synonyms) > 1:
            j = 1
            for i in synonyms:
                synonymsEmbed.add_field(name=f'Synonym {j}', value=i)
                j += 1
        
        else:
            synonymsEmbed.add_field(name='Synonym: ', value=synonyms[0])
        
        await context.message.channel.send(embed=synonymsEmbed)

@client.command(name='get_channels', pass_context=True)
async def get_channels(context):
    _guild = context.message.guild

    channels = await _guild.fetch_channels()
    categories = _guild.categories

    _channelsUnsynced = 0

    warningsEmbed = discord.Embed(title="Warnings.")

    for channel in channels:
        if channel in categories:
            pass
        else:
            if channel.permissions_synced:
                pass
            else:
                _channelsUnsynced += 1
    
    if _channelsUnsynced > 0:
        await context.message.channel.send(f'{_channelsUnsynced} channel(s) are not synced with their categories.')
    
    # warningsEmbed.add_field(name=f'Channel {channel} has perms not synced with category.', value='Severity: 1', inline=False)
    
    # await context.message.channel.send(embed=warningsEmbed)

@client.command(name='fetch', pass_context=True)
async def fetch(context):
    _failed = False
    cmd = context.message.content.split(" ")
    try:
        query = cmd[1].lower()
    except IndexError:
        await context.message.channel.send("Please make sure you enter your query after ./fetch!")
        _failed = True
    
    if not _failed:
        if query == 'neko':
            resp = requests.get(f'https://wallhaven.cc/api/v1/search?q=neko&purity=001&page={random.randrange(1, 12)}&apikey={whAPI}')
            respJSON = resp.json()

            post = secrets.choice(respJSON['data'])
            image_url = post['path']

            await context.message.channel.send(image_url)
    else:
        pass

@client.command(name='join', pass_context=True)
async def join(context):
    _voiceChannels = context.message.guild.voice_channels

    for channel in _voiceChannels:
        if context.message.author in channel.members:
            voiceClient = discord.VoiceClient(client, channel)
            await voiceClient.connect(reconnect=False, timeout=60)
        else:
            pass

@client.command(name='leave', pass_context=True)
async def leave(context):
    _voiceChannels = context.message.guild.voice_channels

    for channel in _voiceChannels:
        if context.message.author in channel.members:
            voiceClient = discord.VoiceClient(client, channel)
            await voiceClient.disconnect(force=True)
        else:
            pass

def returnEncodedTime(key):
    currTime = datetime.datetime.now().time()
    timeFormat = f'{currTime.hour}:{currTime.minute}'
    digest = hmac.new(key, timeFormat.encode(), hashlib.sha256).hexdigest()
    return b64.b64encode(digest.encode()).decode()

@client.command(name='secret', pass_context=True)
async def secretFeature(context):
    key = context.message.author.name.encode()
    try:
        code = context.message.content.split(' ')[1]
    except IndexError:
        pass

    try:
        if code == returnEncodedTime(key):
            await context.message.delete()
            await context.message.channel.send("*gasp* You know the secret?!?!??!?!??!?!?")
        else:
            pass
    except UnboundLocalError:
        pass

def returnLine():
    with open(f'rockyou.txt', 'r') as r:
        while True:
            data = r.readline().strip()
            if not data:
                break
            yield data

@client.command(name='brute', pass_context=True)
async def brute(context):
    cmdSplit = context.message.content.split(' ')
    algo = cmdSplit[1].lower()
    if algo in algos.keys():
        hashToCrack = cmdSplit[-1]
        wrdlst = returnLine()
        password = ""
        found = False
        for entry in wrdlst:
            currHash = algos[algo](str(entry).encode()).hexdigest()
            if currHash == hashToCrack:
                password = entry
                found = True
                break
            else:
                pass
    else:
        await context.message.channel.send('Algorithm not supported! Please choose from MD5, SHA256, or SHA512')
    
    if found:
        await context.message.channel.send(f"Password found: {password}")
    else:
        await context.message.channel.send("Password not found")

@client.command(name='compliment', pass_context=True)
async def compliment(context, member: commands.MemberConverter):
    compliment = secrets.choice(sayings['compliments'])
    await context.message.channel.send(compliment)

@client.command(name='roo', pass_context=True)
async def roo(context):
    embed = discord.Embed(title='Invite my best friend\'s discord bot!', colour=rooColour)
    embed.description = 'Invite [here](https://discord.com/api/oauth2/authorize?client_id=675609879083483136&permissions=0&scope=bot)'
    embed.set_image(url='https://cdn.discordapp.com/avatars/675609879083483136/7b1342f2946db02d9d0f23a0819e0091.webp?size=1024')
    await context.message.channel.send(embed=embed)

@client.command(name='invite', pass_context=True)
async def invite(context):
    embed = discord.Embed(title='Invite me to your server!', colour=0x41e296)
    embed.description = 'Invite [here](https://discord.com/api/oauth2/authorize?client_id=802660359760248833&permissions=201452550&scope=bot)!'
    embed.set_image(url='https://media.vyrix.xyz/apx08ftp/vyrix/default.png')

    await context.message.channel.send(embed=embed)

@client.command(name='guilds', pass_context=True)
async def guilds(context):
    _guilds = client.guilds
    totalMemberCount = 0
    for guild in _guilds:
        totalMemberCount += guild.member_count
    
    await context.message.channel.send(f'I am a member of {len(_guilds)} guilds, and am watching {totalMemberCount} members')

@client.command(name='strlen', pass_context=True)
async def strlen(context):
    SMsg = context.message.content.split(' ')[1:]
    lengthEmbed = discord.Embed(title='Length')
    if len(SMsg) > 1:
        _msg = ' '.join(SMsg)
        withSpaces = len(_msg)
        withoutSpaces = len(''.join(SMsg))
        lengthEmbed.add_field(name='With spaces: ', value=withSpaces)
        lengthEmbed.add_field(name='Without spaces: ', value=withoutSpaces)
    else:
        lengthEmbed.add_field(name='String length: ', value=len(''.join(SMsg)))
    
    await context.message.channel.send(embed=lengthEmbed)

@client.command(name='algorithms', pass_context=True)
async def algorithms(context):
    algoEmbed = discord.Embed(title='Supported Algorithms:')
    algoEmbed.add_field(name='Encoding/Decoding: ', value=f'{", ".join(encoders.keys())}', inline=False)
    algoEmbed.add_field(name='Hashing: ', value=f'{", ".join(algos.keys())}', inline=False)
    await context.message.channel.send(embed=algoEmbed)

@client.command(name='add_reaction', pass_context=True)
async def add_reaction(context, messageid, *reactions):
    authMsg = context.message
    await authMsg.delete()
    msg = await context.fetch_message(messageid)
    for reaction in reactions:
        await msg.add_reaction(reaction)

@client.command(name='pp_size', pass_context=True)
async def pp_size(context, member: commands.MemberConverter=None):
    if member is None:
        await context.message.channel.send('Specify a member!')
    else:
        size = int(secrets.randbelow(200)/10)
        pp = f'8{"="*size}D'
        ppEmbed = discord.Embed(title=f'Inspecting {member.name}\'s penis :microscope:')
        ppEmbed.add_field(name=f'Penis size: ', value=pp)
        await context.message.channel.send(embed=ppEmbed)

@client.command(name='token', pass_context=True)
async def _token(context):
    _token_types = {
        'urlsafe': secrets.token_urlsafe,
        'hex': secrets.token_hex,
        'bytes': secrets.token_bytes
    }

    _error = False

    try:
        _token_type = context.message.content.split(' ')[1].lower()
    except IndexError:
        await context.message.channel.send(f'Supported token types: {", ".join(_token_types)}')
        _error = True
    
    if not _error:
        if _token_type not in list(_token_types.keys()):
            await context.message.channel.send(f'Supported token types: {", ".join(_token_types)}')
        
        else:
            _bytes = context.message.content.split(' ')[2]
            try:
                _bytes = int(_bytes)
            except ValueError:
                await context.message.channel.send('Bytes must be a number.')
                
            if _bytes > 50 or _bytes < 1:
                await context.message.channel.send('Bytes must be 1-50.')
            else:
                result = _token_types[_token_type](_bytes)
                if _token_type == 'bytes':
                    result = str(result)[2:-1]
                await context.message.channel.send(f'`{result}`')

@client.command(name='foxxo', aliases=['fox'], pass_context=True)
async def foxxo(context):
    fox = requests.get('https://randomfox.ca/floof/?ref=apilist.fun').json()
    foxEmbed = discord.Embed(title='Foxxo')
    foxEmbed.set_image(url=fox['image'])
    foxEmbed.set_footer(text=f'URL: {fox["image"]}')

    await context.message.channel.send(embed=foxEmbed)

@client.command(name='help', pass_context=True)
async def help(context):
    sections = commandsJSON['Commands']

    error = False

    try:
        helpQuery = context.message.content.split(' ')[1].title()
    except IndexError:
        await context.message.channel.send("Please choose from a list of these help pages: ")
        helpEmbed = discord.Embed(title='Available help sections: ')
        helpEmbed.description = '[Official Vyrix Website](https://vyrix.xyz/)'
        helpEmbed.set_thumbnail(url='https://media.vyrix.xyz/apx08ftp/vyrix/VYRIX.png')
        for sectNum, section in enumerate(sections, start=1):
            helpEmbed.add_field(name=f'Section {sectNum}', value=section, inline=False)
        
        helpEmbed.add_field(name=f'\nBot developed by: ', value=f"{client.get_user(358029842048090113)}", inline=False)
        await context.message.channel.send(embed=helpEmbed)
        error = True
    
    if error:
        pass
    else:
        if helpQuery in sections:
            cmds = commandsJSON['Commands'][helpQuery][0]
            helpEmbed = discord.Embed(title=f'{helpQuery} Commands: ')
            helpEmbed.description ='[Official Vyrix Website](https://vyrix.xyz/)'
            helpEmbed.set_thumbnail(url='https://media.vyrix.xyz/apx08ftp/vyrix/VYRIX.png')
            for key, value in cmds.items():
                helpEmbed.add_field(name=key, value=value, inline=False)

            if helpQuery == 'Fernet':
                helpEmbed.description ='[Why Fernet?](https://vyrix.xyz/why-fernet)'
                await context.message.channel.send(embed=helpEmbed)
            else:
                await context.message.channel.send(embed=helpEmbed)

# @client.command(name='play', pass_context=True)
# async def play(context):
#     messageIssuer = context.message.author
#     userVCID = messageIssuer.
#     url = context.message.content[7:]
#     ydl_opts = {'format': 'bestaudio'}
#     with youtube_dl.YoutubeDL(ydl_opts) as ydl:
#         info = ydl.extract_info(url, download=False)
#         urlOfContent = info['formats'][0]['url']

# @client.command(name='weather', pass_context = True)
# async def weather(context, location=None):
#     if location == None:
#         await context.message.channel.send('Please specify city ID. Call the ./send_city_ids command to have the list DM\'d to you.')
#     else:
#         location = context.message.content[10::]
#         conf.read('auth.ini')
#         token = conf['AUTH']['weatherToken']

#         response = requests.get(f'api.openweathermap.org/data/2.5/weather?zip={location}&appid={token}')
#         response = response.json()
#         response = response.items()
#         weatherEmbed = discord.Embed(title='Weather.', colour=0x163fc2)

#         temp = 0
#         speed = 0
#         main = ""

#         for key, value in response:
#             if key == main.temp:
#                 temp = key
#             elif key == wind.speed:
#                 speed = key
#             elif key == weather.main:
#                 main = str(key)

#         weatherEmbed.add_field(name='Main weather: ', value=main)
#         weatherEmbed.add_field(name='Temperature: ', value=temp)
#         weatherEmbed.add_field(name='Wind Speed: ', value=speed)
#         await context.message.channel.send(embed=weatherEmbed)

if not args.verbose:
    @client.event
    async def on_command_error(context, exception=[discord.ext.commands.errors.CommandNotFound, discord.ext.commands.errors.CommandInvokeError, discord.ext.commands.errors.MemberNotFound]):
        if isinstance(exception, discord.ext.commands.errors.CommandNotFound):
            failedLogger.info(f'CMD NOT FOUND | {context.message.content} | {context.message.channel} | {context.message.guild}')
        elif isinstance(exception, discord.ext.commands.errors.CommandInvokeError):
            failedLogger.info(f'INVOKE ERROR | {context.message.content} | {context.message.channel} | {context.message.guild}')
        elif isinstance(exception, discord.ext.commands.errors.MemberNotFound):
            failedLogger.info(f'MEMBER NOT FOUND | {context.message.content} | {context.message.channel} | {context.message.guild}')
            await context.message.channel.send('Sorry, that member is not found...')
        else:
            failedLogger.info('Unknown error caught')

@client.event
async def on_command(context):
    pass # because i fucking forgot what i was gonna have here.

@client.event
async def on_command_completion(context):
    try:
        successLogger.info(f'{(context.message.content).split(" ")[0]} | {context.message.author.name} | {context.message.channel.name} | {context.message.guild.name}')
        # print(f"{context.message.content.split(' ')[0]} used by {context.message.author.name} in {context.message.channel.name} in {context.message.guild.name}")
    except AttributeError:
        successLogger.info(f'{(context.message.content).split(" ")[0]} | {context.message.author.name} | DMs')
        # print(f"{context.message.content.split(' ')[0]} used by {context.message.author.name} in DMs")

# @client.event
async def sendMsg(channelid, msg):
    channel = await client.fetch_channel(channelid)
    await channel.send(msg)

def spawnShell(newstdin):
    sys.stdin = newstdin

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    print(loop.is_running())

    _EXITSHELL = False
    guildid = ''
    while not _EXITSHELL:
        commandline = input(">>> ").split(" ")
        if commandline[0] == 'echo':
            print(' '.join(commandline[1:]))
        elif commandline[0] == 'set_guild':
            guildid = commandline[1]
            print(f'set guild id to {guildid}')
        elif commandline[0] == 'send':
            channelid = commandline[1]
            messageToSend = ' '.join(commandline[2:])
            loop.run_until_complete(sendMsg(channelid, messageToSend))
        elif commandline[0] == 'exit':
            _EXITSHELL = True

@client.event
async def on_ready():
    #Guild = await client.fetch_guild(701881057368080525)

    async for guild in client.fetch_guilds(limit=100):
        print(f'Bot loaded for {guild.name}')

    print('Connected to encryption key database.')
    botStatusChannel = client.get_channel(802706944933625876)
    await client.change_presence(status=discord.Status.online, activity=discord.Game('Listening for commands... | vyrix.xyz', type=ActivityType.custom))
    edited = False
    while not edited:
        await botStatusChannel.edit(name="Bot-Status: Online")
        if botStatusChannel.name == 'Bot-Status: Online':
            edited = True
        else:
            continue

    print(f'Started at {datetime.datetime.ctime(datetime.datetime.now())}')
    print("Bot online!")
    
    # newstdin = os.fdopen(os.dup(sys.stdin.fileno()))
    # shellProcess = multiprocessing.Process(target=spawnShell, args=[newstdin])
    # shellProcess.start()

@client.event
async def on_disconnect():
    botStatusChannel = client.get_channel(802706944933625876)
    await botStatusChannel.edit(name="Bot-Status: Offline")

@client.event
async def on_member_join(member: commands.MemberConverter):
    guild = member.guild.id
    if guild == '701881057368080525':
        welcome_channel = client.get_channel(802705006276378665)
        await welcome_channel.send(f"Greetings {member}! Welcome to APX_HUB!")
    else:
        pass

@client.event
async def on_member_leave(member: commands.MemberConverter):
    welcome_channel = client.get_channel(802705006276378665)
    await welcome_channel.send(f"Yikes! Looks like {member} left!")

# @client.event
# async def on_member_ban(guild, member: commands.MemberConverter):
    # await guild.
    # await message.welcome_channel.send(f"Uh oh, {member} got into trouble and got banned!")

@client.event
async def on_message(message):
    if message.author.id == 358029842048090113:
        if message.content.startswith('>./'):
            _msg = message.content[3:]
            await message.delete()
            await message.channel.send(_msg)
    
    if args.log:
        chatLogger.info(f'{message.content} | {message.author.name} | {message.channel.name} | {message.guild.name}')
    
    # try:
    #     if message.author.guild_permissions.administrator:
    #         pass
    #     else:
    #         if len(nwordRegex.findall(message.content)) > 0:
    #             await message.delete()
    # except AttributeError:
    #     pass
    
    # if len(commandRegex.findall(message.content)):
    #     await client.process_commands(message)
    # else:
    #     pass

    await client.process_commands(message)

if checkForTable() and checkForGamesTable():
    client.load_extension('cogs.encodings')
    client.load_extension('cogs.fernet')
    client.load_extension('cogs.games')
    client.load_extension('cogs.conversions')
    client.run(token)
else:
    print('Failed to start, 1 or more DBs lacked tables.')