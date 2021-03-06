from rest_framework import permissions


class BasePermission(permissions.BasePermission):
    permission_class = ''

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        # check for method permission
        return request.user.has_perm(self.permission_class + '_' +
                                     request.method.lower())


class ReadOnly(permissions.BasePermission):

    def has_permission(self, request, view):
        return request.method in permissions.SAFE_METHODS


class IsOwner(permissions.BasePermission):

    def has_object_permission(self, request, view, obj):
        return obj.user == request.user
