#!/usr/bin/env python


from eve import Eve
from eve.auth import TokenAuth
from flask import request, abort, session
import simplejson as json
from uuid import uuid4
from werkzeug.security import check_password_hash, generate_password_hash
import rsa
from binascii import unhexlify
from bson import ObjectId

# Auth.
# (pub_key, priv_key) = rsa.newkeys(512)
# TODO: Test Data
pub_key = rsa.PublicKey(
    8921024716371754727547384565532647500907381374817191290946327694983112049452723924540673075803819034621461214836234237074358644750716368753679466138645029,
    65537)

priv_key = rsa.PrivateKey(
    8921024716371754727547384565532647500907381374817191290946327694983112049452723924540673075803819034621461214836234237074358644750716368753679466138645029,
    65537,
    2009432333843170167814432930350686519193657992508832840028528761361379068113294330465719618280331127547960659713686886615908137101969160746256428478547073,
    5898939169219132166935368737053817192731411646948517184935252674524905845147347729,
    1512310003622680001800762992728322286092053925521211364745816870334303701)


def decrypt(hexstr):
    """
    :param hexstr: A string of HEX of the encrypted data
    :return: A string of decrypted data.
    """
    binary = unhexlify(hexstr)
    decrypted = rsa.decrypt(binary, priv_key)
    decoded = decrypted.decode('utf-8')
    splitted = decoded.split('|', 1)
    return {
        'username': splitted[0],
        'password': splitted[1],
    }


def check_auth_with_db(username, password):
    """
    :param username: A string of username.
    :param password: A string of password.
    :return: True (passed) / False (failed)
    """
    users = app.data.driver.db['users']
    user = users.find_one({'name': username})
    if not user:
        return False
    accounts = app.data.driver.db['accounts']
    oid = str(user['_id'])
    account = accounts.find_one({'user': oid})
    if account and check_password_hash(account['password'], password):
        return oid
    else:
        return False


def check_auth(encrypted):
    """
    :param encrypted: Encrypted string contains the auth info (username, password)
    :return: True (passed) / False (failed)
    """
    decrypted = decrypt(encrypted)
    return check_auth_with_db(decrypted['username'], decrypted['password'])


def update_token(oid):
    sessions = app.data.driver.db['sessions']
    token = str(uuid4())
    sessions.update({'user': oid}, {'user': oid, 'token': token}, upsert=True)
    return token


def get_user_by_token(token):
    sen = app.data.driver.db['sessions'].find_one({'token': token})
    if not sen:
        return None
    else:
        oid = sen['user']
        user = app.data.driver.db['users'].find_one(ObjectId(oid))
        account = app.data.driver.db['accounts'].find_one({'user': oid})
        return user, account


class TokenAuth(TokenAuth):
    def check_auth(self, token, allowed_roles, resource, method):
        (user, account) = get_user_by_token(token)
        if account is not None:
            session['user'] = str(user['_id'])
            return account
        else:
            return None


app = Eve(auth=TokenAuth)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return json.dumps({
            "n": hex(pub_key.n),
            "e": hex(pub_key.e),
        })
    elif request.method == 'POST':
        try:
            is_authed = check_auth(json.loads(request.data.decode('utf-8')))
        except:
            abort(401)
        else:
            if is_authed:
                token = update_token(is_authed)
                return json.dumps(token)
            else:
                abort(401)
    else:
        abort(405)


# Events
def crypt_password(items):
    items[0]['password'] = generate_password_hash(items[0]['password'])


app.on_insert_accounts += crypt_password
app.on_update_accounts += crypt_password


def hide_password(req, res):
    data = json.loads(res.data)
    try:
        del (data['password'])
    except KeyError:
        pass
    res.data = json.dumps(data)


app.on_post_POST_accounts += hide_password
app.on_post_PUT_accounts += hide_password


def check_author_in_posts(req):
    author = json.loads(req.data.decode('utf-8'))['author']
    if author != session['user']:
        abort(401)


app.on_pre_POST_posts += check_author_in_posts

if __name__ == '__main__':
    # TODO: Remove dev code
    app.debug = True
    app.run()
