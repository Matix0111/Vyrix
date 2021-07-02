import discord
import random
import time
from datetime import *
import sqlite3
from dateutil.relativedelta import *
from dateutil.parser import *
import calendar
from collections import Counter
from discord.ext import commands

con = sqlite3.connect('gamedata.db')
cur = con.cursor()

def checkForGamesTable():
    cur.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='users'")
    if cur.fetchone()[0] == 1:
        return True
    else:
        cur.execute('''CREATE TABLE users (userid text, points integer, spun_today bool, can_spin text)''')
        con.commit()
        print('Table now exists')
        return False

class Games(commands.Cog):
    slots = {
        ':apple:': 5,
        ':banana:': 20,
        ':100:': 100
    }

    def __init__(self, client):
        self.client = client
    
    '''
        ACCOUNT SECTION
    '''

    def fetchPoints(self, userid):
        cur.execute('SELECT points FROM users WHERE userid=?', (f"{userid}",))
        try:
            data =  cur.fetchone()
            if data is not None:
                return data[0]
            else:
                cur.execute('''INSERT INTO users VALUES (?, ?, ?, ?)''', (userid, 0, False, ''))
                con.commit()
                return 0

        except TypeError:
            pass
    
    def getDate(self, nextday=False):
        date = datetime.today()
        if not nextday:
            return date
        else:
            dayCanSpin = date + timedelta(days=1)
            return dayCanSpin
    
    def storedDate(self, userid):
        cur.execute('SELECT can_spin FROM users WHERE userid = (?)', (userid,))
        return datetime.strptime(cur.fetchone()[0], '%Y-%m-%d %H:%M:%S.%f')
    
    def canSpin(self, userid):
        cur.execute('SELECT spun_today FROM users WHERE userid = (?)', (userid,))
        if not cur.fetchone():
            return True
    
    def updateSlotStat(self, userid, action):
        if action == 0:
            cur.execute('UPDATE users SET spun_today = (?) WHERE userid = (?)', (True, userid))
            cur.execute('UPDATE users SET can_spin = (?) WHERE userid = (?)', (self.getDate(nextday=True), userid))
            con.commit()
    
    def updatePoints(self, action, userid, points, ret=False):
        if action == 0:
            currentPoints = self.fetchPoints(userid) + points
            cur.execute(f'UPDATE users SET points = (?) WHERE userid = (?)', (currentPoints, userid))
            con.commit()
            return currentPoints
        else:
            newPoints = self.fetchPoints(userid) - points
            cur.execute(f'UPDATE users SET points = (?) WHERE userid = (?)', (newPoints, userid))
            con.commit()
            return newPoints

    '''
        ADMIN SECTION
    '''

    @commands.command()
    @commands.has_permissions(administrator=True)
    async def add_points(self, context, member: commands.MemberConverter=None, amount=0):
        if member is not None and amount > 0:
            newPoints = self.updatePoints(0, member.id, amount, True)
            embed = discord.Embed(title='Add Vyrix Points')
            embed.add_field(name='Value given: ', value=f'{amount:,}')
            embed.add_field(name='Total: ', value=f'{newPoints:,}')
            await context.message.channel.send(embed=embed)

        elif member is None:
            await context.message.channel.send("You must specify a member to add points to.")

        elif amount <= 0:
            await context.message.channel.send("Amount must be greater than 0")
    
    @commands.command()
    @commands.has_permissions(administrator=True)
    async def sub_points(self, context, member: commands.MemberConverter=None, amount=0):
        if member is not None and amount > 0:
            newPoints = self.updatePoints(1, member.id, amount, True)
            embed = discord.Embed(title='Sub Vyrix Points')
            embed.add_field(name='Value removed: ', value=f'{amount:,}')
            embed.add_field(name='Total: ', value=f'{newPoints:,}')
            await context.message.channel.send(embed=embed)

        elif member is not None:
            await context.message.channel.send("You must specify a member to add points to.")

        elif amount <= 0:
            await context.message.channel.send("Amount must be greater than 0")

    '''
        USER SECTION
    '''

    @commands.command()
    async def clear_points(self, context):
        usr = context.message.author.id
        currentPoints = self.fetchPoints(usr)
        self.updatePoints(1, usr, currentPoints)
        if self.fetchPoints(usr) == 0:
            await context.message.channel.send("Vyrix points reset.")

    @commands.command()
    async def give_points(self, context, member: commands.MemberConverter=None, amount=0):
        if member is not None and amount > 0:
            sender = context.message.author.id
            if self.fetchPoints(sender) - amount <= 0:
                await context.message.channel.send("You do not have enough points.")
            else:
                newSenderAmount = self.updatePoints(1, sender, amount, True)
                newRecieverAmount = self.updatePoints(0, member.id, amount, True)
                embed = discord.Embed(title='Give points')
                usr = member.nick
                if member.nick is None:
                    usr = member.name
                embed.add_field(name=f'Given {usr}: ', value=f'{amount:,}')
                embed.add_field(name=f'Your new balance is: ', value=f'{newSenderAmount:,}')
                await context.message.channel.send(embed=embed)
        elif member is not None:
            await context.message.channel.send("You must specify a member to give points to.")

        elif amount <= 0:
            await context.message.channel.send("Amount must be greater than 0")

    @commands.command()
    async def points(self, context, member: commands.MemberConverter=None):
        if member is None:
            userid = context.message.author.id
            pointsAmount = self.fetchPoints(userid)
            pointsEmbed = discord.Embed(title='Vyrix Points')
            pointsEmbed.add_field(name='Your Vyrix Points: ', value=f'{pointsAmount:,}', inline=False)
            await context.message.channel.send(embed=pointsEmbed)
        else:
            userid = member.id
            pointsAmount = self.fetchPoints(userid)
            pointsEmbed = discord.Embed(title='Vyrix Points')
            pointsEmbed.add_field(name=f'{member.name}\'s Vyrix Points: ', value=f'{pointsAmount:,}', inline=False)
            await context.message.channel.send(embed=pointsEmbed)

    '''
        GAMES SECTION
    '''
    
    @commands.command()
    async def roll(self, context):
        failed = False
        usr = context.message.author.id
        try:
            bet = context.message.content.split(' ')[1]
        except IndexError:
            await context.message.channel.send("You must guess a number.")
            failed = True
        
        try:
            bet = int(bet)
        except ValueError:
            await context.message.channel.send("Bet must be a number.")
            failed = True
        except UnboundLocalError:
            pass
        
        if not failed:
            won = False
            if bet > 6 or bet < 0:
                await context.message.channel.send("Bet is invalid. Must be 1-6")
            else:
                roll = random.randrange(1, 7)
                gameEmbed = discord.Embed(title='Dice roll')

                if roll >= bet:
                    if bet + 1 == roll:
                        gameEmbed.add_field(name=f'Rolled a {roll}', value='You win!')
                        won = True
                    elif bet == roll:
                        gameEmbed.add_field(name=f'Rolled a {roll}', value='You win!')
                        won = True
                    else:
                        gameEmbed.add_field(name=f'Rolled a {roll}', value='You lose!')
                elif roll <= bet:
                    if bet - 1 == roll:
                        gameEmbed.add_field(name=f'Rolled a {roll}', value='You win!')
                        won = True
                    elif bet == roll:
                        gameEmbed.add_field(name=f'Rolled a {roll}', value='You win!')
                        won = True
                    else:
                        gameEmbed.add_field(name=f'Rolled a {roll}', value='You lose!')
                else:
                    gameEmbed.add_field(name=f'Rolled a {roll}', value='You lose!')
                
                if not won:
                    pass
                else:
                    self.updatePoints(0, usr, 10)
                await context.message.channel.send(embed=gameEmbed)
    
    @commands.command(aliases=['slots'])
    async def slot(self, context):
        usr = context.message.author.id
        choices = [random.choice(list(self.slots.keys())) for i in range(3)]

        counter = Counter(choices)
        most_occurring = counter.most_common(1)

        amountWon = 0
        
        slotEmbed = discord.Embed(title='Slot Machine')
        if most_occurring[0][1] == 1:
            slotEmbed.add_field(name=f'{choices[0]}{choices[1]}{choices[2]}', value='You didn\'t win anything :<')
        else:
            amountOfMatches = most_occurring[0][1]
            if amountOfMatches < 3:
                amountWon = self.slots[most_occurring[0][0]] * amountOfMatches
            else:
                amountWon = 500
            slotEmbed.add_field(name=f'{choices[0]}{choices[1]}{choices[2]}', value=f'You won {amountWon}!')
        
        self.updatePoints(0, usr, amountWon)
        await context.message.channel.send(embed=slotEmbed)
        # self.updateSlotStat(usr, 0)

        # else:
        #     timetoday = self.getDate()
        #     timeStored = self.storedDate(usr)
        #     delta = timeStored - timetoday
        #     seconds = delta.total_seconds()
        #     minutes = seconds / 60
        #     hours = minutes / 60
        #     time = f'{hours} hours, {minutes} minutes, {seconds} seconds'
        #     await context.message.channel.send(f"You have spun in the past 24 hours. You may spin again in {time}")

    @commands.Cog.listener()
    async def on_ready(self):
        print('Games cog loaded')

def setup(client):
    client.add_cog(Games(client))