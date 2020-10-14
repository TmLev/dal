# Generated by Django 3.1.2 on 2020-10-14 15:17

from django.db import migrations, models
import django.db.models.deletion
import dms.models


class Migration(migrations.Migration):

    dependencies = [
        ('dms', '0007_separate_document_models'),
    ]

    operations = [
        migrations.CreateModel(
            name='Book',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.TextField()),
                ('annotation', models.TextField(blank=True)),
                ('publication_year', models.PositiveSmallIntegerField(default=dms.models.current_year)),
                ('authors', models.ManyToManyField(blank=True, to='dms.Author')),
                ('file', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='dms.file')),
                ('publishers', models.ManyToManyField(blank=True, to='dms.Publisher')),
                ('subjects', models.ManyToManyField(blank=True, to='dms.Subject')),
            ],
            options={
                'verbose_name': 'Book',
                'verbose_name_plural': 'Books',
            },
        ),
    ]
