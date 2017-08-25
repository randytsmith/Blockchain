from authservice.models import User
from rest_framework import serializers


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('email', 'password', 'role')

    def is_valid(self, raise_exception=False):
        valid = super().is_valid(raise_exception)

        if not valid:
            return False

        if hasattr(self, 'initial_data'):
            extra = set(self.initial_data.keys()) - set(self.fields.keys())
            print(extra)
            if extra:
                for k in extra:
                    self._errors[k] = self._errors.get(k, [])
                    self._errors[k].append('This is an extra field.')
                return False
        return True
