from django.conf.urls import url
from django.contrib import admin
from myapp import views

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^$', views.redirect_to_login),
    url(r'^login/$', views.user_login, name='login'),
    url(r'^logout/$', views.user_logout, name='logout'),
    url(r'^admin_page/$', views.admin_page, name='admin_page'),
    url(r'^create_user/$', views.create_user, name='create_user'),
    url(r'^ca_page/$', views.ca_page, name='ca_page'),
    url(r'^doctor_page/$', views.doctor_page, name='doctor_page'),
    url(r'^patient_page/$', views.patient_page, name='patient_page'),
    url(r'^approve_user/(?P<user_id>\d+)/(?P<action>\w+)/$', views.approve_user, name='approve_user'),
    url(r'^send_email/$', views.test_send_email, name='send_email'),
]