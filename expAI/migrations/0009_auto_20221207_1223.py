# Generated by Django 3.2.2 on 2022-12-07 05:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('expAI', '0008_auto_20221204_2315'),
    ]

    operations = [
        migrations.AlterField(
            model_name='class',
            name='classid',
            field=models.AutoField(db_column='classID', primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='datasets',
            name='datasetid',
            field=models.AutoField(db_column='datasetID', primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='evaluations',
            name='evaluateid',
            field=models.AutoField(db_column='evaluateID', primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='models',
            name='modelid',
            field=models.AutoField(db_column='modelID', primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='objects',
            name='objid',
            field=models.AutoField(db_column='objID', primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='results',
            name='resultid',
            field=models.AutoField(db_column='resultID', primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='roles',
            name='roleid',
            field=models.AutoField(db_column='roleID', primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name='softwarelibs',
            name='softwarelibid',
            field=models.AutoField(db_column='softwarelibID', primary_key=True, serialize=False),
        ),
    ]