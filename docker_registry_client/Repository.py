from __future__ import absolute_import

import json
import functools
from .Image import Image


class BaseRepository(object):
    def __init__(self, client, repository, namespace=None):
        self._client = client
        self.repository = repository
        self.namespace = namespace

    @property
    def name(self):
        if self.namespace:
            return "{self.namespace}/{self.repository}".format(self=self)
        return self.repository


class RepositoryV1(BaseRepository):
    def __init__(self, client, repository, namespace=None):
        if namespace is None:
            namespace = 'library'

        super(RepositoryV1, self).__init__(client, repository,
                                           namespace=namespace)
        self._images = None

    def __repr__(self):
        return 'RepositoryV1({name})'.format(name=self.name)

    def refresh(self):
        self._images = self._client.get_repository_tags(self.namespace,
                                                        self.repository)

    def tags(self):
        if self._images is None:
            self.refresh()

        if type(self._images) is list:
            return list(taginfo['name'] for taginfo in self._images)
        else:
            return list(self._images.keys())

    def data(self, tag):
        return self._client.get_tag_json(self.namespace, self.repository, tag)

    def image(self, tag):
        if self._images is None:
            self.refresh()

        image_id = self._images[tag]
        return Image(image_id, self._client)

    def untag(self, tag):
        return self._client.delete_repository_tag(self.namespace,
                                                  self.repository, tag)

    def tag(self, tag, image_id):
        return self._client.set_tag(self.namespace, self.repository,
                                    tag, image_id)

    def delete_repository(self):
        # self._client.delete_repository(self.namespace, self.repository)
        raise NotImplementedError()


class RepositoryV2(BaseRepository):
    def __init__(self, client, repository, namespace=None):
        super(RepositoryV2, self).__init__(client, repository,
                                           namespace=namespace)
        self._tags = None

    def __repr__(self):
        return 'RepositoryV2({name})'.format(name=self.name)

    def tags(self):
        if self._tags is None:
            self.refresh()

        return self._tags

    def manifest(self, tag):
        """
        Return a tuple, (manifest, digest), for a given tag
        """
        return self._client.get_manifest_and_digest(self.name, tag)

    def manifest_schema_2(self, tag):
        """
        Return a tuple, (manifest, digest), for a given tag
        """
        return self._client.get_manifest_and_digest_schema_2(self.name, tag)

    def delete_manifest(self, digest):
        return self._client.delete_manifest(self.name, digest)

    def refresh(self):
        response = self._client.get_repository_tags(self.name)
        self._tags = response['tags']


    def tag_size(self, tag):
        manifest, digest = self.manifest_schema_2(tag)
        return functools.reduce(lambda a, b: a+b, [item['size'] for item in manifest['layers']], 0)

    def tags_by_date(self):
        # based on https://stackoverflow.com/questions/46892589/get-latest-docker-image-creation-date-from-registry
        latest = []
        for tag in self.tags():
            manifest, digest = self.manifest(tag)
            latest.append((tag, json.loads(manifest['history'][0]['v1Compatibility']).get('created')))

        # sort the list based upon created timestamp stored as the second element of the tuple
        latest.sort(key=lambda x: x[1])

        return latest
        # return latest image tag from tuple
        # return latest[-1][0]
    

def Repository(client, *args, **kwargs):
    if client.version == 1:
        return RepositoryV1(client, *args, **kwargs)
    else:
        assert client.version == 2
        return RepositoryV2(client, *args, **kwargs)
