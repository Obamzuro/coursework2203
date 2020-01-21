"""'1'

Revision ID: bfc497b73767
Revises: 
Create Date: 2020-01-21 01:57:11.190783

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'bfc497b73767'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=True),
    sa.Column('email', sa.String(length=120), nullable=True),
    sa.Column('password_hash', sa.String(length=128), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_user_email'), 'user', ['email'], unique=True)
    op.create_index(op.f('ix_user_username'), 'user', ['username'], unique=True)
    # op.drop_table('subject')
    # op.drop_table('student_skill')
    # op.drop_table('lab_result')
    # op.drop_table('skill')
    # op.drop_table('student')
    # op.drop_table('lab')
    # ### end Alembic commands ###


def downgrade():
    pass
    # ### commands auto generated by Alembic - please adjust! ###
    # op.create_table('lab',
    # sa.Column('lab_id', sa.INTEGER(), server_default=sa.text("nextval('lab_lab_id_seq'::regclass)"), autoincrement=True, nullable=False),
    # sa.Column('subject_id', sa.INTEGER(), autoincrement=False, nullable=True),
    # sa.Column('lab_number', sa.INTEGER(), server_default=sa.text('1'), autoincrement=False, nullable=False),
    # sa.CheckConstraint('lab_number > 0', name='lab_number_valid'),
    # sa.ForeignKeyConstraint(['subject_id'], ['subject.subject_id'], name='lab_subject_fk', onupdate='CASCADE', ondelete='SET NULL'),
    # sa.PrimaryKeyConstraint('lab_id', name='lab_pkey'),
    # postgresql_ignore_search_path=False
    # )
    # op.create_table('student',
    # sa.Column('student_id', sa.INTEGER(), server_default=sa.text("nextval('student_student_id_seq'::regclass)"), autoincrement=True, nullable=False),
    # sa.Column('student_name', sa.TEXT(), autoincrement=False, nullable=False),
    # sa.Column('student_surname', sa.TEXT(), autoincrement=False, nullable=True),
    # sa.Column('student_course', sa.INTEGER(), server_default=sa.text('1'), autoincrement=False, nullable=False),
    # sa.Column('student_studybook', sa.INTEGER(), autoincrement=False, nullable=False),
    # sa.CheckConstraint('(student_course > 0) AND (student_course < 7)', name='student_course_valid'),
    # sa.PrimaryKeyConstraint('student_id', name='student_pkey'),
    # postgresql_ignore_search_path=False
    # )
    # op.create_table('skill',
    # sa.Column('skill_id', sa.INTEGER(), server_default=sa.text("nextval('skill_skill_id_seq'::regclass)"), autoincrement=True, nullable=False),
    # sa.Column('subject_id', sa.INTEGER(), autoincrement=False, nullable=True),
    # sa.Column('skill_grade', sa.VARCHAR(length=3), autoincrement=False, nullable=True),
    # sa.ForeignKeyConstraint(['subject_id'], ['subject.subject_id'], name='skill_subject_id_fkey', onupdate='CASCADE', ondelete='SET NULL'),
    # sa.PrimaryKeyConstraint('skill_id', name='skill_pkey'),
    # postgresql_ignore_search_path=False
    # )
    # op.create_table('lab_result',
    # sa.Column('lab_result_id', sa.INTEGER(), autoincrement=True, nullable=False),
    # sa.Column('lab_id', sa.INTEGER(), autoincrement=False, nullable=True),
    # sa.Column('student_id', sa.INTEGER(), autoincrement=False, nullable=True),
    # sa.Column('is_passed', sa.BOOLEAN(), autoincrement=False, nullable=False),
    # sa.ForeignKeyConstraint(['lab_id'], ['lab.lab_id'], name='lab_result_lab_fk', onupdate='CASCADE', ondelete='SET NULL'),
    # sa.ForeignKeyConstraint(['student_id'], ['student.student_id'], name='lab_result_student_id_fkey', onupdate='CASCADE', ondelete='CASCADE'),
    # sa.PrimaryKeyConstraint('lab_result_id', name='lab_result_pkey')
    # )
    # op.create_table('student_skill',
    # sa.Column('student_skill_id', sa.INTEGER(), autoincrement=True, nullable=False),
    # sa.Column('student_id', sa.INTEGER(), autoincrement=False, nullable=False),
    # sa.Column('skill_id', sa.INTEGER(), autoincrement=False, nullable=False),
    # sa.ForeignKeyConstraint(['skill_id'], ['skill.skill_id'], name='student_skill_skill_id_fkey', onupdate='CASCADE', ondelete='CASCADE'),
    # sa.ForeignKeyConstraint(['student_id'], ['student.student_id'], name='student_skill_student_id_fkey', onupdate='CASCADE', ondelete='CASCADE'),
    # sa.PrimaryKeyConstraint('student_id', 'skill_id', name='student_skill_id')
    # )
    # op.create_table('subject',
    # sa.Column('subject_id', sa.INTEGER(), autoincrement=True, nullable=False),
    # sa.Column('subject_name', sa.TEXT(), autoincrement=False, nullable=False),
    # sa.PrimaryKeyConstraint('subject_id', name='subject_pkey')
    # )
    # op.drop_index(op.f('ix_user_username'), table_name='user')
    # op.drop_index(op.f('ix_user_email'), table_name='user')
    # op.drop_table('user')
    # ### end Alembic commands ###