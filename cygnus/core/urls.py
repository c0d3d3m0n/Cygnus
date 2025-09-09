# from django.urls import path
# from core.views import dashboard_view, add_target

# urlpatterns = [
#     path('', dashboard_view, name='home'),  # Add this line for the root URL
#     path('dashboard/<int:session_id>/', dashboard_view, name='dashboard'),
#     path('api/targets/', add_target, name='add_target'),
# ]

from django.urls import path
from . import views

urlpatterns = [
    # Main dashboard view
    path('', views.dashboard_view, name='dashboard'),

    # API Endpoints for Targets and Sessions
    path('api/targets/', views.add_target, name='add_target'),
    path('api/sessions/', views.list_sessions, name='list_sessions'),

    # API Endpoints for starting scans (grouped by session)
    path('api/sessions/<int:session_id>/scan/', views.start_scan, name='start_scan'),
    path('api/sessions/<int:session_id>/recon/', views.start_recon, name='start_recon'),

    # API Endpoints for retrieving results (grouped by session)
    # path('api/sessions/<int:session_id>/results/', views.get_scan_results, name='get_scan_results'),
    path('api/sessions/<int:session_id>/scans/', views.get_scan_results, name='get_scan_results'),
    path('api/sessions/<int:session_id>/subdomains/', views.get_subdomains, name='get_subdomains'),
    path('api/sessions/<int:session_id>/ports/', views.get_ports, name='get_ports'),

    # API Endpoint for report generation
    path('api/sessions/<int:session_id>/report/<str:format>/', views.generate_report, name='generate_report'),
]