from rest_framework.permissions import SAFE_METHODS, IsAuthenticated


class ShellUIPermission(IsAuthenticated):
    """
    Authenticated users only; personal access tokens with ``pat_ro`` are read-only (safe methods).
    """

    def has_permission(self, request, view):
        if not super().has_permission(request, view):
            return False
        auth = getattr(request, 'auth', None)
        if auth is None:
            return True
        pat_ro = auth.get('pat_ro') if hasattr(auth, 'get') else None
        if pat_ro is True and request.method not in SAFE_METHODS:
            return False
        return True
