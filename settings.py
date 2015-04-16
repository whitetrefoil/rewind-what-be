#!/usr/bin/env python

from uuid import uuid4

SECRET_KEY = str(uuid4())

# MongoDB Settings.
MONGO_HOST = 'localhost'
MONGO_PORT = 27017
# MONGO_USERNAME = 'user'
# MONGO_PASSWORD = 'user'
MONGO_DBNAME = 'rewind-what'

# Global API Settings.
ALLOWED_FILTERS = []
RESOURCE_METHODS = ['GET']
ITEM_METHODS = ['GET']
PAGINATION_LIMIT = 200
PAGINATION_DEFAULT = 50
PROJECTION = False
BANDWIDTH_SAVER = False

# Resources Settings.
DOMAIN = {
    'posts': {
        'resource_methods': ['GET', 'POST'],
        'item_methods': ['GET'],
        'schema': {
            'content': {
                'type': 'string',
                'minlength': 1,
                'required': True,
            },
            'author': {
                'data_relation': {
                    'resource': 'users'
                },
                'required': True,
            }
        }
    },
    'users': {
        'resource_methods': ['POST'],
        'item_methods': [],
        'schema': {
            'name': {
                'type': 'string',
                'minlength': 1,
                'required': True,
                'unique': True
            }
        }
    },
    'accounts': {
        'resource_methods': ['POST'],
        'item_methods': [],
        'authentication': None,
        'hateoas': False,
        'schema': {
            'user': {
                'data_relation': {
                    'resource': 'users'
                },
                'type': 'string',
                'unique': True,
                'required': True,
            },
            'password': {
                'type': 'string',
                'required': True,
            }
        },
        'query_objectid_as_string': True
    },
    'sessions': {
        'resource_methods': ['POST'],
        'item_methods': [],
        'auth_field': 'user',
        'hateoas': False,
        'schema': {
            'user': {
                'data_relation': {
                    'resource': 'users'
                },
                'unique': True
            },
            'token': {
                'type': 'string',
                'required': True,
            }
        }
    }
}

if __name__ == '__main__':
    pass
