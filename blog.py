import os
import re
import random
import hashlib
import hmac
import codecs
import time
from string import letters
import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'fart'

#<-Basics---------------------------->

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

#<-BlogHandler---------------------------->

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.render('front.html')


def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

#<-Users---------------------------->

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

#<-db models---------------------------->

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    user = db.ReferenceProperty(User,
                                required=True,
                                collection_name="blogs")

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class Comment(db.Model):
    user = db.ReferenceProperty(User, required=True)
    post = db.ReferenceProperty(Post, required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    text = db.TextProperty(required=True)

    @classmethod
    def cdb_blog_id(cls, blog_id):
        c = Comment.all().filter('post =', blog_id)
        return c.count()

    @classmethod
    def adb_blog_id(cls, blog_id):
        c = Comment.all().filter('post =', blog_id).order('created')
        return c

class Like(db.Model):
    user = db.ReferenceProperty(User, required=True)
    post = db.ReferenceProperty(Post, required=True)

    @classmethod
    def dbl_blog_id(cls, blog_id):
        l = Like.all().filter('post =', blog_id)
        return l.count()

    @classmethod
    def likes(cls, blog_id, user_id):
        cl = Like.all().filter('post =', blog_id).filter('user =', user_id)
        return cl.count()

class Unlike(db.Model):
    user = db.ReferenceProperty(User, required=True)
    post = db.ReferenceProperty(Post, required=True)

    @classmethod
    def dbu_blog_id(cls, blog_id):
        ul = Unlike.all().filter('post =', blog_id)
        return ul.count()

    @classmethod
    def unlikes(cls, blog_id, user_id):
        cul = Unlike.all().filter('post =', blog_id).filter('user =', user_id)
        return cul.count()

#<-Posts, Comments, Likes------------------->

class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts = posts)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        likes = Like.dbl_blog_id(post)
        unlikes = Unlike.dbu_blog_id(post)
        post_comments = Comment.adb_blog_id(post)
        comments_count = Comment.cdb_blog_id(post)

        self.render("permalink.html", post = post, likes = likes,
                                      unlikes = unlikes,
                                      post_comments = post_comments,
                                      comments_count = comments_count)

    def post(self, post_id):
        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        post = db.get(key)
        user_id = User.by_name(self.user.name)
        comments_count = Comment.cdb_blog_id(post)
        post_comments = Comment.adb_blog_id(post)
        likes = Like.dbl_blog_id(post)
        unlikes = Unlike.dbu_blog_id(post)
        previously_liked = Like.likes(post, user_id)
        previously_unliked = Unlike.unlikes(post, user_id)

        if self.user:
            if self.request.get("like"):
                if post.user.key().id() != User.by_name(self.user.name).key().id():
                    if previously_liked == 0:
                        l = Like(post = post, user = User.by_name(self.user.name))
                        l.put()
                        time.sleep(0.1)
                        self.redirect('/post/%s' % str(post.key().id()))
                    else:
                        error = "You can only like a post once"
                        self.render("post.html", post = post, likes = likes,
                                                 unlikes = unlikes,
                                                 error = error,
                                                 comments_count = comments_count,
                                                 post_comments = post_comments)
                else:
                    error = "You cannot like your own posts"
                    self.render("post.html", post = post, likes = likes,
                                             unlikes = unlikes, error = error,
                                             comments_count = comments_count,
                                             post_comments = post_comments)
            if self.request.get("unlike"):
                if post.user.key().id() != User.by_name(self.user.name).key().id():
                    if previously_unliked == 0:
                        ul = Unlike(post = post, user = User.by_name(self.user.name))
                        ul.put()
                        time.sleep(0.1)
                        self.redirect('/post/%s' % str(post.key().id()))
                    else:
                        error = "You can only unlike a post once"
                        self.render("post.html", post = post, likes = likes,
                                                 unlikes = unlikes,
                                                 error = error,
                                                 comments_count = comments_count,
                                                 post_comments = post_comments)
                else:
                    error = "You cannot unlike your own posts"
                    self.render("post.html", post = post, likes = likes,
                                             unlikes = unlikes, error = error,
                                             comments_count = comments_count,
                                             post_comments = post_comments)
            if self.request.get("add_comment"):
                comment_text = self.request.get("comment_text")
                if comment_text:
                    c = Comment(post = post, user = User.by_name(
                                self.user.name), text = comment_text)
                    c.put()
                    time.sleep(0.1)
                    self.redirect('/post/%s' % str(post.key().id()))
                else:
                    comment_error = "Please enter a comment"
                    self.render("post.html", post = post, likes = likes,
                                             unlikes = unlikes,
                                             comments_count = comments_count,
                                             post_comments = post_comments,
                                             comment_error = comment_error)
            if self.request.get("edit"):
                if post.user.key().id() == User.by_name(self.user.name).key().id():
                    self.redirect('/edit/%s' % str(post.key().id()))
                else:
                    error = "You may only edit your own posts"
                    self.render("post.html", post = post, likes = likes,
                                             unlikes = unlikes,
                                             comments_count = comments_count,
                                             post_comments = post_comments,
                                             error = error)
            if self.request.get("delete"):
                if post.user.key().id() == User.by_name(self.user.name).key().id():
                    db.delete(key)
                    time.sleep(0.1)
                    self.redirect('/')
                else:
                    error = "You may only delete your own posts"
                    self.render("post.html", post = post, likes = likes,
                                             unlikes = unlikes,
                                             comments_count = comments_count,
                                             post_comments = post_comments,
                                             error = error)
        else:
            self.redirect("/login")

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')
        user_id = User.by_name(self.user.name)

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content, user = user_id)
            p.put()
            self.redirect('/post/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

class EditPost(BlogHandler):

    def get(self, blog_id):
        key = db.Key.from_path("Post", int(blog_id), parent=blog_key())
        post = db.get(key)

        if self.user:
            if post.user.key().id() == User.by_name(self.user.name).key().id():
                self.render("editpost.html", post=post)
            else:
                self.response.out.write("You cannot edit other user's posts")
        else:
            self.redirect("/login")

    def post(self, blog_id):
        key = db.Key.from_path("Post", int(blog_id), parent=blog_key())
        post = db.get(key)

        if self.request.get("update"):

            subject = self.request.get("subject")
            content = self.request.get("content").replace('\n', '<br>')

            if post.user.key().id() == User.by_name(self.user.name).key().id():
                if subject and content:
                    post.subject = subject
                    post.content = content
                    post.put()
                    time.sleep(0.1)
                    self.redirect('/post/%s' % str(post.key().id()))
                else:
                    post_error = "Please enter a subject and the blog content"
                    self.render("editpost.html", subject = subject,
                                                 content = content,
                                                 post_error = post_error)
            else:
                self.response.out.write("You cannot edit other user's posts")
        elif self.request.get("cancel"):
            self.redirect('/post/%s' % str(post.key().id()))

class DeletePost(BlogHandler):
    def get(self, post_id):
        key = db.Key('Post', int(post_id), parent=models.blog_key())
        post = key.get()
        if not post:
            self.error(404)
            return
        if self.user:
            self.render('deletepost.html', post=post)
        else:
            error = "You need to login to delete a post."
            self.render('login.html', error=error)

    def post(self, post_id):
        if not self.user:
            return self.redirect('/login')
        key = ndb.Key('Post', int(post_id), parent=models.blog_key())
        post = key.get()

        if post and (post.author.id() == self.user.key.id()):
            post.key.delete()
            time.sleep(0.1)
            self.redirect('/')

class DeleteComment(BlogHandler):

    def get(self, post_id, comment_id):
        comment = Comment.get_by_id(int(comment_id))
        if comment:
            if comment.user.name == self.user.name:
                db.delete(comment)
                time.sleep(0.1)
                self.redirect('/post/%s' % str(post_id))
            else:
                self.write("You cannot delete other user's comments")
        else:
            self.write("This comment no longer exists")

class EditComment(BlogHandler):

    def get(self, post_id, comment_id):
        post = Post.get_by_id(int(post_id), parent=blog_key())
        comment = Comment.get_by_id(int(comment_id))
        if comment:
            if comment.user.name == self.user.name:
                self.render("editcomment.html", comment_text=comment.text)
            else:
                error = "You cannot edit other users' comments'"
                self.render("editcomment.html", edit_error=error)
        else:
            error = "This comment no longer exists"
            self.render("editcomment.html", edit_error=error)

    def post(self, post_id, comment_id):
        if self.request.get("update_comment"):
            comment = Comment.get_by_id(int(comment_id))
            if comment.user.name == self.user.name:
                comment.text = self.request.get('comment_text')
                comment.put()
                time.sleep(0.1)
                self.redirect('/post/%s' % str(post_id))
            else:
                error = "You cannot edit other users' comments'"
                self.render(
                    "editcomment.html",
                    comment_text=comment.text,
                    edit_error=error)
        elif self.request.get("cancel"):
            self.redirect('/post/%s' % str(post_id))

#<-Lesson HW -------------------------->

class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Unit2Signup(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)

class Register(Signup):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

class Unit3Welcome(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/unit2/rot13', Rot13),
                               ('/unit2/signup', Unit2Signup),
                               ('/unit2/welcome', Welcome),
                               ('/blog/?', BlogFront),
                               ('/post/([0-9]+)', PostPage),
                               ('/newpost', NewPost),
                               ('/edit/([0-9]+)', EditPost),
                               ('/delete/([0-9]+)', DeletePost),
                               ('/blog/([0-9]+)/editcomment/([0-9+])', EditComment),
                               ('/blog/([0-9]+)/deletecomment/([0-9+])', DeleteComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/unit3/welcome', Unit3Welcome),
                               ],
                              debug=True)
