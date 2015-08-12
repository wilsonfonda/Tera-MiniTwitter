import unittest
import json
import datetime
import fakeredis
from pytz import timezone
from contextlib import contextmanager
import sys
import os
import boto
from moto import mock_s3
from StringIO import StringIO

import tera


@contextmanager
def captured_output():
    new_out, new_err = StringIO(), StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err


class TestTera(unittest.TestCase):

    def set_s3_DB(self):
        tera.bucket = ['foo-1', 'foo-2']

    def index(self, userID):
        if not userID:
            return self.app.get('/', follow_redirects=True)
        else:
            return self.app.get('/%s' % userID, follow_redirects=True)

    def signin(self, email, password):
        return self.app.post('/signin', data=dict(
            logEmail=email,
            logPassword=password
        ), follow_redirects=True)

    def signup(self, firstName, lastName, email, password):
        return self.app.post('/signup', data=dict(
            inputFirstName=firstName,
            inputLastName=lastName,
            suEmail=email,
            suPassword=password
        ), follow_redirects=True)

    def signout(self):
        return self.app.get('/signout', follow_redirects=True)

    def share(self, inputPost, uploadImg):
        return self.app.post('/share', data=dict(
            inputPost=inputPost,
            uploadImg=uploadImg
        ), follow_redirects=True)

    def deletePost(self, inputPostID):
        return self.app.post('/deletepost', data=dict(
            inputPostID=inputPostID
        ), follow_redirects=True)

    def editPost(self, editPostID, inputEditPost, editImg):
        return self.app.post('/editpost', data=dict(
            editPostID=editPostID, editImg=editImg,
            inputEditPost=inputEditPost
        ), follow_redirects=True)

    def search(self, inputSearch):
        return self.app.post('/search', data=dict(
            inputSearch=inputSearch
        ), follow_redirects=True)

    def follow(self, followUserID):
        return self.app.post('/followuser', data=dict(
            followUserID=followUserID
        ), follow_redirects=True)

    def unfollow(self, unfollowUserID):
        return self.app.post('/unfollowuser', data=dict(
            unfollowUserID=unfollowUserID
        ), follow_redirects=True)

    def loginplus(self):
        return self.app.get('/loginplus', follow_redirects=True)

    def setUp(self):
        self.app = tera.app.test_client()
        tera.r_server = fakeredis.FakeRedis()
        self.redis = tera.r_server
        self.signup('first', 'last', 'test@email.com', 'testtest')
        self.signout()
        self.signup('first2', 'last2', 'test2@email.com', 'testtest')
        self.signout()

    def tearDown(self):
        self.signout()
        self.redis.flushall()
        del self.redis

    def test_allowed_file(self):
        self.assertFalse(tera.allowed_file('test.txt'))
        self.assertTrue(tera.allowed_file('test.png'))

    def create_redis(self, db='localhost'):
        return fakeredis.FakeRedis(db=db)

    def test_signin_signout(self):
        rv = self.signin('', 'test')
        assert 'invalid email address' in rv.data
        rv = self.signin('test', 'testtest')
        assert 'invalid email address' in rv.data
        rv = self.signin('test@email.com', '')
        assert 'invalid password' in rv.data
        rv = self.signin('test@email.com', 'wrongpass')
        assert 'invalid password' in rv.data
        rv = self.signin('test@email.com', 'testtest')
        assert 'successfully signed in' in rv.data
        rv = self.signin('test@email.com', 'testtest')
        assert 'you are already signed in' in rv.data
        rv = self.signout()
        assert 'successfully signed out' in rv.data
        rv = self.signout()
        assert 'you are not signed in' in rv.data

    def test_signup_signin_signout(self):
        rv = self.signup('', '', '', '')
        assert 'You have to enter your first name' in rv.data
        assert 'You have to enter your last name' in rv.data
        assert 'You have to enter a valid email address' in rv.data
        assert 'You have to enter a password' in rv.data
        rv = self.signup('', '', 'test@email.com', 'aaa')
        assert 'The email already exist' in rv.data
        assert 'Your password must be between 8-36 character' in rv.data
        rv = self.signup('', '', 'test@email.com', 'a'*37)
        assert 'The email already exist' in rv.data
        assert 'Your password must be between 8-36 character' in rv.data
        self.assertEqual('2', self.redis.get('next_userID'))
        rv = self.signup('first', 'last', 'wils@email.com', 'wilsontest')
        assert 'successfully signed up' in rv.data
        self.assertEqual('3', self.redis.get('next_userID'))
        rv = self.signout()
        assert 'successfully signed out' in rv.data
        rv = self.signin('wils@email.com', 'wilsontest')
        assert 'successfully signed in' in rv.data
        assert 'first' in rv.data
        assert 'last' in rv.data
        assert 'wils@email.com' in rv.data
        assert 'Sign out' in rv.data
        rv = self.signout()
        assert 'successfully signed out' in rv.data

    def test_index(self):
        rv = self.index(None)
        assert 'Sign in' in rv.data
        assert 'Join Us Now!' in rv.data
        rv = self.signin('test@email.com', 'testtest')
        assert 'Share' in rv.data
        rv = self.index('1')
        assert "Share" in rv.data
        rv = self.index('2')
        assert "first2's Timeline" in rv.data

    @mock_s3
    def test_share(self):
        tera.conn = boto.connect_s3()
        tera.bucket = tera.conn.create_bucket('mybucket')
        filename = 'test.txt'
        temp = open(filename, 'w+b')
        rv = self.share('', '')
        assert 'You are not signed in' in rv.data
        self.signin('test@email.com', 'testtest')
        rv = self.share(None, None)
        assert 'Please write your thoughts first' in rv.data
        s = 'a'*301
        rv = self.share(s, temp)
        assert 'Your thought is too long' in rv.data
        assert 'Please upload correct file' in rv.data
        temp.close()
        os.remove(filename)
        filename = 'test.jpg'
        temp = open(filename, 'w+b')
        rv = self.share('asdffsdfavzxc', temp)
        assert '1.jpg' in rv.data
        assert 'asdffsdfavzxc' in rv.data
        rv = self.app.get('/share', follow_redirects=True)
        assert 'your thought is abstract' in rv.data
        temp.close()
        os.remove(filename)

    def test_deletePost(self):
        rv = self.deletePost("1")
        assert 'You are not signed in' in rv.data
        self.signin('test@email.com', 'testtest')
        rv = self.deletePost(None)
        assert 'ID is unavailable' in rv.data
        self.share('test', None)
        rv = self.app.get('/deletepost', follow_redirects=True)
        assert 'you are not allowed to delete the post' in rv.data
        self.signout()
        self.signin('test2@email.com', 'testtest')
        rv = self.deletePost("1")
        assert 'you are not allowed to delete the post' in rv.data
        self.signout()
        self.signin('test@email.com', 'testtest')
        rv = self.deletePost('1')
        print rv.data
        assert 'deletion successfull' in rv.data

    def test_editePost(self):
        rv = self.editPost("1", "changed content", None)
        assert 'You are not signed in' in rv.data
        self.signin('test@email.com', 'testtest')
        rv = self.editPost(None, "changed content", None)
        assert 'ID is unavailable' in rv.data
        self.share('test', None)
        rv = self.app.get('/editpost', follow_redirects=True)
        assert 'you are not allowed to edit the post' in rv.data
        rv = self.editPost("1", None, None)
        assert 'You should put some thoughts' in rv.data
        rv = self.editPost("1", "changed content", None)
        assert "edit successfull" in rv.data
        self.signout()
        self.signin('test2@email.com', 'testtest')
        rv = self.editPost("1", "changed content", None)
        assert 'you are not allowed to edit the post' in rv.data

    def test_search(self):
        rv = self.search('first2')
        assert 'You are not signed in' in rv.data
        self.signin('test@email.com', 'testtest')
        rv = self.search('first')
        assert 'test2@email.com' in rv.data
        assert 'test@email.com' not in rv.data
        rv = self.search('first2')
        assert 'test2@email.com' in rv.data
        assert 'test@email.com' not in rv.data
        rv = self.search('last2')
        assert 'test2@email.com' in rv.data
        assert 'test@email.com' not in rv.data
        rv = self.search('test2@email.co')
        assert 'test2@email.com' in rv.data
        assert 'test@email.com' not in rv.data
        rv = self.search('')
        assert 'test2@email.com' in rv.data
        rv = self.app.get('/search', follow_redirects=True)
        assert 'Unable to search' in rv.data

    def test_follow(self):
        rv = self.follow("1")
        assert "You are not signed in" in rv.data
        self.signin('test@email.com', 'testtest')
        rv = self.app.get('/followuser', follow_redirects=True)
        assert 'Unable to follow' in rv.data
        rv = self.follow(None)
        assert 'Invalid account' in rv.data
        assert 'Failed to follow' in rv.data
        rv = self.follow('2')
        assert 'successfully follow the account' in rv.data
        assert 'following 1 | followers 0' in rv.data
        rv = self.follow('2')
        assert 'You already follow this person' in rv.data
        assert 'Failed to follow' in rv.data

    def test_unfollow(self):
        rv = self.unfollow("2")
        assert "You are not signed in" in rv.data
        self.signin('test@email.com', 'testtest')
        rv = self.app.get('/unfollowuser', follow_redirects=True)
        assert 'Please choose who you want to unfollow' in rv.data
        rv = self.unfollow(None)
        assert 'Invalid account' in rv.data
        assert 'Failed to unfollow' in rv.data
        rv = self.unfollow('2')
        assert "You are not following this person" in rv.data
        assert 'Failed to unfollow' in rv.data
        rv = self.follow('2')
        rv = self.unfollow('2')
        assert 'successfully unfollow the account' in rv.data
        rv = self.unfollow('2')
        assert "You are not following this person" in rv.data
        assert 'Failed to unfollow' in rv.data

    def test_loginplus(self):
        with self.app.session_transaction() as sess:
            with open('credentials.json', 'r') as data_file:
                j = json.load(data_file)
                j['token_expiry'] = datetime.datetime.now(timezone(
                    'UTC')).strftime("%Y-%m-%dT%H:%M:%S")
                sess['credentials'] = json.dumps(j)
        rv = self.loginplus()
        print rv.data
        assert 'service built' in rv.data
        assert 'You are registered using google plus' in rv.data
        self.signout()
        with self.app.session_transaction() as sess:
            with open('credentials.json', 'r') as data_file:
                j = json.load(data_file)
                j['token_expiry'] = datetime.datetime.now(timezone(
                    'UTC')).strftime("%Y-%m-%dT%H:%M:%S")
                sess['credentials'] = json.dumps(j)
        rv = self.loginplus()
        assert 'You sign in through google plus' in rv.data
        self.signout()


if __name__ == '__main__':
    unittest.main()
