from drf_writable_nested import WritableNestedModelSerializer
from rest_framework.serializers import (Serializer, ModelSerializer,
                                        IntegerField, DateField,
                                        SerializerMethodField, CharField)
from rest_framework.serializers import ValidationError

from common.models.subjects import Subject

from lms.models.lesson import Lesson
from lms.models.mark import Mark
from lms.models.student import Student
from lms.models.common import Milgroup
from lms.serializers.lesson import LessonSerializer
from lms.serializers.student import StudentShortSerializer

from lms.validators import PresentInDatabaseValidator


class MarkSerializer(WritableNestedModelSerializer):
    student = StudentShortSerializer(
        required=False, validators=[PresentInDatabaseValidator(Student)])
    lesson = LessonSerializer(
        required=False, validators=[PresentInDatabaseValidator(Lesson)])

    def validate(self, attrs):
        student_id = attrs['student']['id']
        student_milgroup = Student.objects.get(id=student_id).milgroup.milgroup
        lesson_id = attrs['lesson']['id']
        lesson_milgroup = Lesson.objects.get(id=lesson_id).milgroup.milgroup
        if student_milgroup != lesson_milgroup:
            raise ValidationError(
                'student milgroup and lesson milgroup should be equal')
        return attrs

    class Meta:
        model = Mark
        fields = '__all__'


class MarkJournalGetQuerySerializer(Serializer):
    milgroup = IntegerField(
        required=True,
        validators=[PresentInDatabaseValidator(Milgroup, 'milgroup')])
    date_from = DateField(required=False)
    date_to = DateField(required=False)
    subject = CharField(
        required=True,
        validators=[PresentInDatabaseValidator(Subject, 'title')]
    )

    def validate(self, attrs):
        if attrs['date_from'] > attrs['date_to']:
            raise ValidationError(
                'date_from should be greater or equal to date_to')
        return attrs

    def create(self, validated_data):
        pass

    def update(self, instance, validated_data):
        pass


class MarkShortSerializer(ModelSerializer):

    class Meta:
        model = Mark
        fields = ['id', 'mark']


class MarkJouralSerializer(ModelSerializer):
    fullname = SerializerMethodField(read_only=True)
    marks = SerializerMethodField(read_only=True)

    class Meta:
        model = Student
        fields = ['id', 'fullname', 'marks']

    def get_fullname(self, obj):
        return f'{obj.surname} {obj.name} {obj.patronymic}'

    def get_marks(self, obj):
        marks = obj.mark_set.filter(
            lesson__date__in=self.context['date_range'],
            lesson__subject__title=self.context['subject']
        )
        return MarkShortSerializer(marks, many=True).data
