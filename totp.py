#!/usr/bin/env python3

import base64
import hmac
import struct


key = 'YNZEDHN2EKEC3EUN7PPHNXIJCPNZDXR3' # Clé secrète encodée en Base32

# 1.	Il faut commencer par convertir la date de la démo en secondes. Ce nombre corresponds au
# nombre de seconde écoulée depuis l’Epoch.
seconds = 1618933182 # Nombre de secondes entre l'Epoch et mardi 20/04/21 à 17:39:42

# 2.	On divise ce nombre par 30 pour obtenir le nombre de périodes de 30 secondes depuis l’Epoch.
counter = int(seconds / 30)

# 3.	Il faut maintenant convertir le compteur en bytes(8). Cette valeur sera appelée message.
message = struct.pack('>Q', counter)

# 4.	On décode la clef (Celle-ci est encodée en base32 pour plus de lisibilité).
b32_key = base64.b32decode(key)

# 5.	Maintenant que la clé et le compteur sont en bytes et grâce à un algorithme de hachage,
# on peut en récupérer un HMAC.
mac = hmac.new(b32_key, message, 'sha1').digest()

# 6.	On peut récupérer la dernière valeur du HMAC, cette valeur sera appelée l’offset.
offset = mac[-1] & 0xf

# 7.	Dans le HMAC et à partir de la position indiquée par l’offset, il faut récupérer les 4
# prochains bytes et leur appliquer le masque 0x7FFFFFFF. Ce masque n’est bien entendu, pas pris
# au hasard. Il permet de s’assurer que la valeur à laquelle le masque est appliqué, sera une valeur
# stockable dans un entier signé. (0x7FFFFFFF = 2147483647. Cette valeur est le dernier entier signé
# possible).
long_code = struct.unpack('>L', mac[offset:offset + 4])[0] & 0x7fffffff

# 8.	Et voici la dernière étape. De ce long code, il suffit de récupérer les 6 dernier chiffres,
# qui donneront le code TOTP.
code = long_code % 10 ** 6

print(code)
