import typing as tp
import asyncio
import operator

from api.client import client
from api.student import (
    Student,
    State,
)

from utils.auth import auth_required


def create_body(student: Student) -> dict:
    return {
        'student': student.id,
        'absence_type': student.type,
        'absence_status': student.status,
    }


def absence_statistic(students: list[Student]) -> str:
    absent_students = [i for i in students if i.state == State.absent]
    text = f'''
Список студентов отправлен!

По списку: {len(students)}
Налицо: {len(students) - len(absent_students)}
Отсутствуют: {len(absent_students)}

ФИО отсутствующих студентов:
'''
    for student in sorted(absent_students,
                          key=operator.attrgetter('full_name')):
        text = '\n'.join([text, student.full_name])
    return text


@auth_required
async def post_absence(
    students: list[Student],
    *args: tp.Any,
    **kwargs: tp.Any
) -> str:
    absent_students = [
        student for student in students
        if student.state.value == State.absent.value
    ]
    tasks = []
    for student in absent_students:
        body = create_body(student)
        tasks.append(client.post('lms/absences/', json=body, *args, **kwargs))
    await asyncio.gather(*tasks)
    return absence_statistic(students)
