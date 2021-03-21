#!/usr/bin/python3

import csv
import click
import os
import string
import secrets
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyperclip
import shutil

usb_loc="/media/viz/V"
salt_loc= "/media/viz/V/namak.csv"
pepper_loc = "/media/viz/Shared/kalimirch.csv"
def getall():
    with open(pepper_loc, newline='') as kalimirch:
        fieldnames = ['account', 'encpass']
        reader = csv.DictReader(kalimirch, fieldnames=fieldnames)
        all_accs=[]
        for row in reader:
            all_accs.append(row['account'])
        return all_accs

def setsalt(acc):
    with open(salt_loc,newline='') as namak:
        fieldnames=['account','salt']
        reader = csv.DictReader(namak,fieldnames=fieldnames)
        for row in reader:
            if row['account'] == acc:
                return 0                                    # Account already exists

    salt = secrets.token_urlsafe(32)
    with open(salt_loc,'a',newline='') as namak:
        fieldnames=['account','salt']
        writer = csv.DictWriter(namak,fieldnames=fieldnames)
        writer.writerow({'account':acc,'salt':salt})
    return salt                                                # Account salt created

def getsalt(acc):
    with open(salt_loc,newline='') as namak:
        fieldnames=['account','salt']
        reader = csv.DictReader(namak,fieldnames=fieldnames)
        for row in reader:
            if row['account'] == acc:
                return row['salt']
        return 0                                               # Account does not exist

def removesalt(acc):
    salt={}
    existed=False
    with open(salt_loc,newline='') as namak:
        fieldnames=['account','salt']
        reader = csv.DictReader(namak,fieldnames=fieldnames)
        for row in reader:
            if row['account'] != acc:
                salt[row['account']]=row['salt']
            else:
                existed=True

    if not existed:
        return 0

    with open(salt_loc,'w',newline='') as namak:
        fieldnames=['account','salt']
        writer = csv.DictWriter(namak,fieldnames=fieldnames)
        for account in iter(salt):
            writer.writerow({'account':account,'salt':salt[account]})
    return 1



def isUSBinserted():
    return os.path.ismount(usb_loc)

def lowerpass(password,start,end):
    l = len(password)
    start = (ord(start)+1)%l
    end = (ord(end)+2)%l
    if start>end:
        start,end=end,start
    print(start)
    print(end)
    return password[:start]+password[start:end].lower()+password[end:]

def upperpass(password,start,end):
    l = len(password)
    start = (ord(start)-1)%l
    end = (ord(end)-2)%l
    if start>end:
        start,end=end,start
    print(start)
    print(end)
    return password[:start]+password[start:end].upper()+password[end:]

def createnewpass(acc,masterpass,upper=True,special=True,length=16):
    specialchars="@#$"
    specialchar=""
    if special:
        length-=1
        specialchar = secrets.choice(specialchars)

    passalpha = ''.join(secrets.choice(string.ascii_lowercase) for i in range(length-1))
    passnum = secrets.choice(string.digits)
    if upper:
        passalpha = passalpha[0].upper() + passalpha[1:]

    password = passalpha+passnum+specialchar
    return password

def encryptpass(plaintext,masterpass,salt):
    salt = salt.encode('UTF-8')
    plaintext = plaintext.encode('UTF-8')
    masterpass = masterpass.encode('UTF-8')
    kdf = PBKDF2HMAC(algorithm = hashes.SHA256(),length = 32,salt = salt,iterations = 100000)
    key = base64.urlsafe_b64encode(kdf.derive(masterpass))
    f = Fernet(key)
    encryptedpass = f.encrypt(plaintext)
    encryptedpass = encryptedpass.decode('UTF-8')
    return encryptedpass
def decryptpass(encryptedext,masterpass,salt):
    try:
        salt = salt.encode('UTF-8')
        encryptedext = encryptedext.encode('UTF-8')
        masterpass = masterpass.encode('UTF-8')
        kdf = PBKDF2HMAC(algorithm = hashes.SHA256(),length = 32,salt = salt,iterations = 100000)
        key = base64.urlsafe_b64encode(kdf.derive(masterpass))
        f = Fernet(key)
        plaintextpass = f.decrypt(encryptedext)
        plaintextpass = plaintextpass.decode('UTF-8')
        return plaintextpass
    except:
        return 0
def writepass(acc,encryptedpass):
    with open(pepper_loc,'a',newline='') as kalimirch:
        fieldnames=['account','encpass']
        writer = csv.DictWriter(kalimirch,fieldnames=fieldnames)
        writer.writerow({'account':acc,'encpass':encryptedpass})

def readpass(acc):
    with open(pepper_loc, newline='') as kalimirch:
        fieldnames = ['account', 'encpass']
        reader = csv.DictReader(kalimirch, fieldnames=fieldnames)
        for row in reader:
            if row['account'] == acc:
                return row['encpass']
        return 0


def removepass(acc):
    encpass= {}
    existed = False
    with open(pepper_loc, newline='') as kalimirch:
        fieldnames = ['account', 'encpass']
        reader = csv.DictReader(kalimirch, fieldnames=fieldnames)
        for row in reader:
            if row['account'] != acc:
                encpass[row['account']] = row['encpass']
            else:
                existed = True

    if not existed:
        return 0

    with open(pepper_loc, 'w', newline='') as kalimirch:
        fieldnames = ['account', 'encpass']
        writer = csv.DictWriter(kalimirch, fieldnames=fieldnames)
        for account in iter(encpass):
            writer.writerow({'account': account, 'encpass': encpass[account]})
    return 1

def addacc(acc,masterpass,length):
    salt = setsalt(acc)
    if salt == 0:
        print("Account salt already exists!")
        return 0
    print("Salt sprinkled")
    password = createnewpass(acc=acc,masterpass=masterpass,length=length)
    encpass = encryptpass(password,masterpass,salt)
    writepass(acc,encpass)
    print("Password copied to clipboard!")
    pyperclip.copy(password)
    return 1

def getacc(acc,masterpass):
    salt = getsalt(acc)
    encpass = readpass(acc)

    if salt == 0:
        print("Account salt does not exist")
    if encpass == 0:
        print("Account pass does not exist")

    if salt==0 or encpass==0:
    	return 0

    print("Salt sprinkled")
    password = decryptpass(encpass,masterpass,salt)
    if password == 0:
        print("Incorrect MasterPass!")
        return 0
    print("Password copied to clipboard!")
    pyperclip.copy(password)
    return 1

def removeacc(acc):
    saltRemovalStatus = removesalt(acc)
    if saltRemovalStatus == 0:
        print("Salt does not exist.")
    else:
        print("Salt found. Removing...")

    passRemovalStatus = removepass(acc)
    if passRemovalStatus == 0:
        print("Password does not exist.")
    else:
        print("Password found. Removing...")


# Click commands under the group passvault

@click.group()
def passvault():
    '''This password manager is made by Viz.'''

    if isUSBinserted() == False:
        click.secho("Please sprinkle salt!",fg='red')
        raise click.Abort
    pass

@click.command()
@click.option('-m','--master','masterpass',required=True,type=str,prompt=True,hide_input=True,confirmation_prompt=True)
@click.option('--acc',required=True,type=str,prompt=True)
@click.option('-l','--length',default=16,type=int)
def add(masterpass,acc,length):
    '''Add password to the manager, l is an optional length parameter'''

    click.secho("Adding new account...",fg='blue',bold=True)
    addacc(acc,masterpass,length)

@click.command()
@click.option('-m','--master','masterpass',required=True,type=str,prompt=True,hide_input=True)
@click.option('--acc',required=True,type=str,prompt=True)
def getpass(masterpass,acc):
    '''Get the password for account.'''

    click.secho("Getting password...",fg='blue',bold=True)
    getacc(acc,masterpass)


@click.command()
@click.option('--acc',required=True,type=str,prompt=True)
def remove(acc):
    '''Remove account'''

    click.secho("Removing account...",fg='red',bold=True)
    removeacc(acc)

@click.command()
def all():
    '''List all stored accounts'''

    all_accs = getall()
    for acc in all_accs:
            click.secho(acc,fg='blue',bold=True)

@click.command()
@click.option('-d','--dest',default="/home/viz/bin/")
def backup(dest):
    '''Create backup at specified path'''
    if not os.path.isfile(pepper_loc):
        click.secho("Shared storage is not mounted",fg='red')
        raise click.Abort
    if not os.path.isfile(salt_loc):
        click.secho("Salt does not exist or is not mounted",fg='red')
        raise click.Abort
    
    try:
        click.secho('Creating backup...',fg="blue",bold=True)
        shutil.copyfile(pepper_loc,dest+"backup_kalimirch.csv")
        shutil.copyfile(salt_loc,dest+"backup_namak.csv")
        click.secho('Backup created successfully',fg="blue")

    except:
        click.secho("Filepath is wrong or permission denied",fg='red')
        raise click.Abort
    



passvault.add_command(add)
passvault.add_command(getpass)
passvault.add_command(remove)
passvault.add_command(all)
passvault.add_command(backup)

if __name__ == '__main__':
    passvault()