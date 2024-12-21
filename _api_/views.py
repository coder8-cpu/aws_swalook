from rest_framework.views import APIView
from rest_framework.generics import CreateAPIView,RetrieveAPIView,UpdateAPIView,ListAPIView,DestroyAPIView
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.parsers import JSONParser
from rest_framework.permissions import IsAuthenticated,AllowAny
from rest_framework.decorators import permission_classes
from rest_framework.exceptions import NotFound
# from silk.profiling.profiler import silk_profile
from django.contrib import auth
from django.contrib.auth.models import User
from django.contrib.auth import authenticate # type: ignore
from django.db.models.signals import post_save, post_delete
import json
from django.db.models import Sum
from django.db.models import Count,Q
from django.db.models import F, Value
from django.db.models.functions import ExtractWeekDay, Coalesce
from django.db import transaction
from django.http import HttpResponse
from django.core.cache import cache
import io
import logging
from api_swalook import urls
from rest_framework.exceptions import ValidationError
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
import requests
from .serializer import *
from rest_framework.permissions import IsAuthenticated
from django.core.exceptions import ObjectDoesNotExist
from django.dispatch import receiver
from django.utils.cache import get_cache_key
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from django.core.mail import send_mail
import datetime as dt
from django.shortcuts import render
from .analysis import *
from .models import *
import random as r
import matplotlib.pyplot as plt
import pandas as pd
from api_swalook.settings import WP_INS_TOKEN,WP_INS_ID,WP_API_URL
import os
import matplotlib
from api_swalook.settings import BASE_DIR
# import magic
from django.core.mail import EmailMessage
from rest_framework import status









class VendorSignin(CreateAPIView):
    permission_classes = [AllowAny]
    serializer_class = signup_serializer

    def post(self, request):

        try:

            serializer_objects = self.serializer_class(data=request.data)


            if serializer_objects.is_valid():

                serializer_objects.save()


                return Response({
                    'success': True,
                    'status_code': status.HTTP_201_CREATED,
                    'error': {
                        'code': 'The request was successful',
                        'message': 'User_created'
                    },
                    'data': {
                        'user': serializer_objects.validated_data.get('salon_name'),
                        'mobileno': serializer_objects.validated_data.get('mobile_no'),
                    }
                }, status=status.HTTP_201_CREATED)
            else:

                return Response({
                    'success': False,
                    'status_code': status.HTTP_400_BAD_REQUEST,
                    'error': {
                        'code': 'The request was unsuccessful',
                        'message': serializer_objects.errors
                    }
                }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:

            return Response({
                'success': False,
                'status_code': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'error': {
                    'code': 'Internal Server Error',
                    'message': str(e)
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
















class vendor_update_profile(APIView):
    permission_classes = [IsAuthenticated]
    def put(self,request):
        serializer_objects           = UpdateProfileSerializer(request.data)                 # convertion of request.data into python native datatype
        json_data                    = JSONRenderer().render(serializer_objects.data)      # rendering the data into json
        stream_data_over_network     = io.BytesIO(json_data)                                 # streaming the data into bytes
        accept_json_stream           = JSONParser().parse(stream_data_over_network)            # prases json data types data
        ''' passing the json stream data into serializer '''

        serializer                   = UpdateProfileSerializer(data=accept_json_stream,context={'request':request})               # intializing serializer and
        if serializer.is_valid():                                                                   # check if serializer.data is valid
                                                                                    # all the .validate_fieldname in the serializer will call here
            ''' here the db call happen after accept  '''

            serializer.save()
            return Response({
                    'success': True,
                    'status_code': status.HTTP_201_CREATED,
                    'error': {
                        'code': 'The request was successful',
                        'message': 'User data updated'
                    },
                    'data':None
                }, status=status.HTTP_201_CREATED)
        return Response({
                'success': False,
                'status_code': status.HTTP_400_BAD_REQUEST,
                'error': {
                    'code': 'The request was successful',

                },
                'data':None
            }, status=status.HTTP_400_BAD_REQUEST)





class vendor_login(CreateAPIView):

    serializer_class = login_serializer
    permission_classes = [AllowAny]
    def post(self,request):
        ''' deserialization of register user'''
        serializer_objects           = login_serializer(request.data)                 # convertion of request.data into python native datatype
        json_data                    = JSONRenderer().render(serializer_objects.data)      # rendering the data into json
        stream_data_over_network     = io.BytesIO(json_data)                                 # streaming the data into bytes
        accept_json_stream           = JSONParser().parse(stream_data_over_network)            # prases json data types data
        ''' passing the json stream data into serializer '''

        serializer                   = login_serializer(data=accept_json_stream,context={"request":request})               # intializing serializer and
        if serializer.is_valid():                                                                   # check if serializer.data is valid
                                                                                    # all the .validate_fieldname in the serializer will call here
            ''' here the db call happen after accept  '''

            serializer.save()                                                       # the create method of serializer call here
            ''' returning the status and info as response'''
            user = User.objects.get(username=request.user)
            token = Token.objects.get_or_create(user=user)
            salon_name = SwalookUserProfile.objects.get(mobile_no=str(request.user))
            if salon_name.branches_created != 0:
                branch = SalonBranch.objects.get(vendor_name=user)
                return Response({
                'status':True,                                                      # corresponding to ---> 'key:value' for access data
                'code': 302,
                'text' : "login successfull !",
                'token': str(token[0]),
                'user': str(request.user),
                'salon_name':salon_name,
                'type':"vendor",

                'branch_name':branch.branch_name,
                })
            else:




                return Response({
                    'status':True,                                                      # corresponding to ---> 'key:value' for access data
                    'code': 302,
                    'text' : "login successfull !",
                    'token': str(token[0]),
                    'user': str(request.user),
                    'salon_name':salon_name,
                    'type':"vendor",




                },)
        return Response({
            'status':False,
            'code':500,
            'text':'invalid user&pass'

        },)

class staff_login(CreateAPIView):

    serializer_class = staff_login_serializer
    permission_classes = [AllowAny]
    def post(self,request):
        ''' deserialization of register user'''
        serializer_objects           = staff_login_serializer(request.data)                 # convertion of request.data into python native datatype
        json_data                    = JSONRenderer().render(serializer_objects.data)      # rendering the data into json
        stream_data_over_network     = io.BytesIO(json_data)                                 # streaming the data into bytes
        accept_json_stream           = JSONParser().parse(stream_data_over_network)            # prases json data types data
        ''' passing the json stream data into serializer '''

        serializer                   = staff_login_serializer(data=accept_json_stream,context={"request":request})               # intializing serializer and
        if serializer.is_valid():                                                                   # check if serializer.data is valid
                                                                                    # all the .validate_fieldname in the serializer will call here
            ''' here the db call happen after accept  '''

            u=serializer.save()                                                       # the create method of serializer call here
            ''' returning the status and info as response'''
            use = SwalookUserProfile.objects.get(mobile_no=str(u.username))
            user = auth.authenticate(username=use.mobile_no,password=use.enc_pwd)
            auth.login(request,user)
            # user = User.objects.get(username=request.user)
            token = Token.objects.get_or_create(user=user)
            salon_name = SwalookUserProfile.objects.get(mobile_no=str(request.user))
            user = User.objects.get(username=salon_name.mobile_no)
            branch = SalonBranch.objects.get(vendor_name=user)






            return Response({
                'status':True,                                                      # corresponding to ---> 'key:value' for access data
                'code': 302,
                'text' : "login successfull !",
                'token': str(token[0]),
                'user': str(request.user),
                'salon_name':salon_name.salon_name,
                'type':"staff",

                'branch_name':branch.branch_name,


            },)
        return Response({
            'status':False,
            'code':500,
            'text':'invalid user&pass'

        },)

class admin_login(CreateAPIView):

    serializer_class = admin_login_serializer
    permission_classes = [AllowAny]
    def post(self,request):
        ''' deserialization of register user'''
        serializer_objects           = admin_login_serializer(request.data)                 # convertion of request.data into python native datatype
        json_data                    = JSONRenderer().render(serializer_objects.data)      # rendering the data into json
        stream_data_over_network     = io.BytesIO(json_data)                                 # streaming the data into bytes
        accept_json_stream           = JSONParser().parse(stream_data_over_network)            # prases json data types data
        ''' passing the json stream data into serializer '''

        serializer                   = admin_login_serializer(data=accept_json_stream,context={"request":request})               # intializing serializer and
        if serializer.is_valid():                                                                   # check if serializer.data is valid
                                                                                    # all the .validate_fieldname in the serializer will call here
            ''' here the db call happen after accept  '''

            token = serializer.save()
            # user = auth.authenticate(username=u.username,password=u.password)
            # the create method of serializer call here
            ''' returning the status and info as response'''



            salon_name = SwalookUserProfile.objects.get(mobile_no=str(request.user))
            user = User.objects.get(username=salon_name.mobile_no)
            branch = SalonBranch.objects.get(vendor_name=user)





            return Response({
                'status':True,                                                      # corresponding to ---> 'key:value' for access data
                'code': 302,
                'text' : "login successfull !",
                'token': str(token[0]),
                'user': str(request.user),
                'salon_name':salon_name,
                'type':"admin",
                'branch_name':branch.branch_name,

            },)
        return Response({
            'status':False,
            'code':500,
            'text':'invalid user&pass'

        },)







class Centralized_login(APIView):
    serializer_class = centralized_login_serializer
    permission_classes = [AllowAny]

    @transaction.atomic

    def post(self, request):

        serializer = self.serializer_class(data=request.data, context={"request": request})

        if serializer.is_valid():
            try:
                result = serializer.create(serializer.validated_data)



                user_type, token, salon_name, branch = result
                # salon_name = SwalookUserProfile.objects.get(mobile_no=str(request.user))
                # branch = SalonBranch.objects.filter(vendor_name=User.objects.get(username=salon_name.mobile_no)).first()

                response_data = {
                    'success': True,
                    'status_code': status.HTTP_200_OK,
                    'error': {
                        'code': 'The request was successful',
                        'message': "login successful!",
                    },
                    'data': {
                        'token': str(token),
                        'user': str(request.user),
                        'salon_name': salon_name,
                        'type': user_type
                    }
                }

                if branch:
                    response_data['data'].update({
                        'branch_name': branch.branch_name,
                        'branch_id': branch.id
                    })

                return Response(response_data, status=status.HTTP_200_OK)

            except ValidationError as e:
                return Response({
                    'success': False,
                    'status_code': status.HTTP_400_BAD_REQUEST,
                    'error': {
                        'code': 'The request was unsuccessful',
                        'message': str(e),
                    },
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

        return Response({
            'success': False,
            'status_code': status.HTTP_400_BAD_REQUEST,
            'error': {
                'code': 'The request was unsuccessful',
                'message': 'Invalid input data',
            },
            'data': None
        }, status=status.HTTP_400_BAD_REQUEST)
class VendorServices(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        branch_name = request.query_params.get('branch_name')




        queryset = VendorService.objects.filter(user=request.user, vendor_branch_id=branch_name).only("id","service").order_by('service')


        serialized_data = service_name_serializer(queryset, many=True)

        return Response({
            'success': True,
            'status_code': status.HTTP_200_OK,

            'data': {
                'service': serialized_data.data,
            }
        }, status=status.HTTP_200_OK)






class Add_vendor_service(CreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = service_serializer

    def post(self, request):
        branch_name = request.query_params.get('branch_name')


        if not branch_name:
            return Response({
                'success': False,
                'status_code': status.HTTP_400_BAD_REQUEST,
                'error': {
                    'code': 'branch_name_missing',
                    'message': 'Branch name is required.',
                },
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)


        service_obj = VendorService.objects.filter(
            user=request.user,
            vendor_branch_id=branch_name,
            service=request.data.get('service')
        )
        if service_obj.exists():
            return Response({
                'success': False,
                'status_code': status.HTTP_409_CONFLICT,
                'error': {
                    'code': 'service_exists',
                    'message': 'A service with the same name already exists on this branch.',
                },
                'data': None
            }, status=status.HTTP_409_CONFLICT)


        serializer = self.serializer_class(data=request.data, context={'request': request, 'branch_id': branch_name})


        if serializer.is_valid():

            serializer.save()

            return Response({
                'success': True,
                'status_code': status.HTTP_201_CREATED,
                'error': {
                    'code': 'service_added',
                    'message': 'Service added successfully on this branch.',
                },
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)


        return Response({
            'success': False,
            'status_code': status.HTTP_400_BAD_REQUEST,
            'error': {
                'code': 'invalid_data',
                'message': 'Provided data is invalid.',
            },
            'data': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)



class Edit_service(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = service_update_serializer

    def put(self, request):
        id = request.query_params.get('id')
        branch_name = request.query_params.get('branch_name')


        service_obj = VendorService.objects.filter(user=request.user, vendor_branch_id=branch_name, service=request.data.get('service')).exclude(id=id)
        if service_obj.exists():
            return Response({
                'success': False,
                'status_code': status.HTTP_200_OK,
                'error': {
                    'code': 'The request was successful',
                    'message': 'Service with the same name already exists on this branch!'
                },
                'data': None
            }, status=status.HTTP_200_OK)


        try:
            service_instance = VendorService.objects.get(id=id, user=request.user, vendor_branch_id=branch_name)
        except VendorService.DoesNotExist:
            return Response({
                'success': False,
                'status_code': status.HTTP_404_NOT_FOUND,
                'error': {
                    'code': 'Not Found',
                    'message': 'Service not found!'
                },
                'data': None
            }, status=status.HTTP_404_NOT_FOUND)


        serializer = self.serializer_class(instance=service_instance, data=request.data, context={'request': request, 'branch_id': branch_name})

        if serializer.is_valid():
            serializer.save()
            return Response({
                'success': True,
                'status_code': status.HTTP_200_OK,
                'error': {
                    'code': 'The request was successful',
                    'message': 'Service updated on this branch!'
                },
                'data': None
            }, status=status.HTTP_200_OK)

        return Response({
            'success': False,
            'status_code': status.HTTP_400_BAD_REQUEST,
            'error': {
                'code': 'Validation Error',
                'message': 'Serializer data is invalid!'
            },
            'data': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)






class Delete_service(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        id = request.query_params.get('id')


        if not id:
            return Response({
                'success': False,
                'status_code': status.HTTP_400_BAD_REQUEST,
                'error': {
                    'code': 'Bad Request',
                    'message': 'ID parameter is missing!'
                },
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

        try:

            queryset = VendorService.objects.get(id=id, user=request.user)
            queryset.delete()

            return Response({
                'success': True,
                'status_code': status.HTTP_200_OK,
                'error': {
                    'code': 'The request was successful',
                    'message': 'Service deleted successfully!'
                },
                'data': None
            }, status=status.HTTP_200_OK)

        except VendorService.DoesNotExist:

            return Response({
                'success': False,
                'status_code': status.HTTP_404_NOT_FOUND,
                'error': {
                    'code': 'Not Found',
                    'message': 'Service not found!'
                },
                'data': None
            }, status=status.HTTP_404_NOT_FOUND)






class Delete_invoice(APIView):
    permission_classes = [IsAuthenticated]
    def delete(self,request,):
        id = request.query_params.get('id')
        queryset = VendorInvoice.objects.get(id=id)
        queryset.delete()

        return Response({
            'success':True,
            'status_code': status.HTTP_200_OK,
            'error': {
                'code': 'The request was successful',


            },
            'data':None


        }, status=status.HTTP_200_OK)






class Table_service(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        branch_name = request.query_params.get('branch_name')





        query_set = VendorService.objects.filter(user=request.user).order_by('service')


        serializer_obj = service_serializer(query_set, many=True)

        return Response({
            "status": True,
            "data": serializer_obj.data
        }, status=status.HTTP_200_OK)

class get_slno(APIView):
    permission_classes = [AllowAny]
    @transaction.atomic
    def get(self, request):

        current_date = dt.date.today()
        current_month = current_date.month
        current_year = current_date.year









        try:

            user_profile = SwalookUserProfile.objects.get(mobile_no=str(request.user))


            user_profile.invoice_generated += 1
            user_profile.save()


            slno = (
                f"{user_profile.vendor_id.lower()}"
                f"{user_profile.invoice_generated}"
                f"{current_month}"
                f"{current_year}"
                f"{user_profile.invoice_generated}"
            )


            return Response({"slno": slno}, status=status.HTTP_200_OK)

        except SwalookUserProfile.DoesNotExist:

            return Response({
                "success": False,
                "error": {
                    "code": "Not Found",
                    "message": "User profile not found."
                }
            }, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:

            return Response({
                "success": False,
                "error": {
                    "code": "Server Error",
                    "message": str(e)
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class vendor_billing(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = billing_serializer

    def __init__(self, **kwargs):
        self.cache_key = None
        super().__init__(**kwargs)

    def dispatch(self, request, *args, **kwargs):
        self.cache_key = f"VendorBilling/{request.user.id}"
        return super().dispatch(request, *args, **kwargs)
    @transaction.atomic
    def post(self, request):
        branch_name = request.query_params.get('branch_name')
        if not branch_name:
            return Response({
                'success': False,
                'status_code': status.HTTP_400_BAD_REQUEST,
                'error': {
                    'code': 'Bad Request',
                    'message': 'branch_name parameter is missing!'
                },
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)
        serializer = self.serializer_class(data=request.data, context={'request': request, 'branch_id': branch_name})

        if serializer.is_valid():
            slno = serializer.save()
            return Response({
                "status": True,
                "slno": slno,
                "message": "Billing record created successfully."
            }, status=status.HTTP_201_CREATED)

        return Response({
            "status": False,
            "errors": serializer.errors,
            "message": "Failed to create billing record."
        }, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        branch_name = request.query_params.get('branch_name')
        if not branch_name:
            return Response({
                'success': False,
                'status_code': status.HTTP_400_BAD_REQUEST,
                'error': {
                    'code': 'Bad Request',
                    'message': 'branch_name parameter is missing!'
                },
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)


        queryset = VendorInvoice.objects.filter(
            vendor_name=request.user,

            date=dt.date.today()
        ).order_by('-date')

        serializer = billing_serializer_get(queryset, many=True)




        return Response({
            "status": True,
            "table_data": serializer.data,
            # "salon_name": salon_profile.salon_name,
            "message": "Billing records retrieved successfully."
        }, status=status.HTTP_200_OK)




class vendor_billing_pdf(CreateAPIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            serializer = self.get_serializer(data=request.data,context={"request":request})
            if not serializer.is_valid():
                return Response({"status": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


            serializer.save()
            if serializer.validated_data.get('email'):
                if not self.send_invoice_email(serializer.validated_data, request.data):
                    return Response({"status": False, "error": "Failed to send email"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({"status": True}, status=status.HTTP_201_CREATED)

        except Exception as e:

            return Response({"status": False, "error": "An unexpected error occurred"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_serializer(self, *args, **kwargs):
        return Vendor_Pdf_Serializer(*args, **kwargs)

    def send_invoice_email(self, validated_data, request_data):
        try:

            subject = f"{validated_data.get('vendor_branch_name')} - Invoice"
            body = (
                f"Hi {request_data.get('customer_name')}!\n"
                f"We hope you had a pleasant experience at {request_data.get('vendor_branch_name')}.\n"
                "We are looking forward to servicing you again. Attached is the invoice.\n"
                f"Thanks and Regards,\nTeam {request_data.get('vendor_branch_name')}"
            )
            from_email = validated_data.get('vendor_email')
            recipient_list = [validated_data.get('email')]


            return self._send_email(subject, body, from_email, recipient_list, validated_data.get('invoice'))

        except Exception as e:

            return False

    def _send_email(self, subject, body, from_email, recipient_list, invoice_id):
        try:

            invoice_filename = f"Invoice-{invoice_id}.pdf"
            invoice_path = os.path.join(settings.MEDIA_ROOT, f"pdf/{invoice_filename}")

            if not os.path.exists(invoice_path):

                return False


            email = EmailMessage(subject, body, from_email, recipient_list)
            with open(invoice_path, 'rb') as invoice_file:
                email.attach(invoice_filename, invoice_file.read(), 'application/pdf')

            email.send()
            return True

        except FileNotFoundError as e:

            return False
        except Exception as e:

            return False
class VendorAppointments(CreateAPIView, ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = appointment_serializer

    def __init__(self):
        self.cache_key = None

    def dispatch(self, request, *args, **kwargs):
        self.cache_key = f"Vendorappointment/{request.user}"
        return super().dispatch(request, *args, **kwargs)

    def post(self, request):
        branch_name = request.query_params.get("branch_name", "").replace("%20", " ")


        existing_appointments = VendorAppointment.objects.filter(
            vendor_name=request.user,
            vendor_branch_id=branch_name,
            mobile_no=request.data.get('mobile_no'),
            booking_date=request.data.get("booking_date"),
            booking_time=request.data.get('booking_time')
        ).exclude(id=branch_name)

        if existing_appointments.exists():
            return Response({
                'status': False,
                'text': f"Appointment for this customer {request.data.get('mobile_no')} on {request.data.get('booking_date')} at {request.data.get('booking_time')} already exists."
            })


        serializer = appointment_serializer(data=request.data, context={"request": request, "branch_id": branch_name})
        if serializer.is_valid():
            serializer.save()
            return Response({"status": True})

        return Response({"status": False, "errors": serializer.errors})

    def list(self, request):
        branch_name = request.query_params.get('branch_name')
        query_set = VendorAppointment.objects.filter(vendor_name=request.user, vendor_branch_id=branch_name,date=dt.date.today()).order_by('-id')
        serializer_obj = appointment_serializer(query_set[::-1], many=True)

        return Response({
            "status": True,
            "table_data": serializer_obj.data,
        })


class edit_appointment(APIView):
    permission_classes = [IsAuthenticated]

    @transaction.atomic
    def put(self, request):

        appointment_id = request.query_params.get('id')
        branch_name = request.query_params.get('branch_name', "").replace("%20", " ")

        if not branch_name or not appointment_id:
            return Response({
                'status': False,
                'error': 'Branch name and appointment ID are required.'
            }, status=400)


        existing_appointments = VendorAppointment.objects.filter(
            vendor_name=request.user,
            vendor_branch_id=branch_name,
            mobile_no=request.data.get('mobile_no'),
            booking_date=request.data.get('booking_date'),
            booking_time=request.data.get('booking_time')
        ).exclude(id=appointment_id)

        if existing_appointments.exists():
            return Response({
                'status': False,
                'error': f"Appointment for customer {request.data.get('mobile_no')} on {request.data.get('booking_date')} at {request.data.get('booking_time')} already exists."
            }, status=409)


        try:
            appointment = VendorAppointment.objects.get(id=appointment_id, vendor_name=request.user)
        except VendorAppointment.DoesNotExist:
            raise NotFound('Appointment not found.')


        data = request.data.copy()
        data['vendor_branch_id'] = branch_name
        data['date'] = dt.date.today()


        serializer = UpdateAppointmentSerializer(appointment, data=data, partial=True, context={"request": request})
        if serializer.is_valid():
            serializer.save()
            return Response({
                'status': True,
                'message': "Appointment updated successfully."
            }, status=200)
        else:
            return Response({
                'status': False,
                'errors': serializer.errors
            }, status=400)





class delete_appointment(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        appointment_id = request.query_params.get('id')


        if not appointment_id:
            return Response({
                "status": False,
                "code": 400,
                "message": "Appointment ID is required."
            }, status=400)

        try:

            appointment = VendorAppointment.objects.get(id=appointment_id, vendor_name=request.user)


            appointment.delete()

            return Response({
                "status": True,
                "code": 200,
                "message": "Appointment successfully deleted.",
                "appointment_deleted_id": appointment_id,
            }, status=200)

        except VendorAppointment.DoesNotExist:

            return Response({
                "status": False,
                "code": 404,
                "message": f"Appointment with ID {appointment_id} does not exist.",
            }, status=404)

        except Exception as e:

            return Response({
                "status": False,
                "code": 500,
                "message": f"An error occurred: {str(e)}",
            }, status=500)


class edit_profile(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, *args, **kwargs):
        mobile_no = request.query_params.get('id')


        if not mobile_no:
            return Response({
                'status': False,
                'code': 400,
                'text': "Mobile number is required."
            }, status=400)

        try:

            profile = SwalookUserProfile.objects.get(mobile_no=mobile_no)
        except SwalookUserProfile.DoesNotExist:
            return Response({
                'status': False,
                'code': 404,
                'text': "Profile not found."
            }, status=404)


        serializer = UpdateProfileSerializer(profile, data=request.data, context={"request": request}, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response({
                'status': True,
                'code': 200,
                'text': "User profile updated successfully!",
                'data': serializer.data
            })

        return Response({
            'status': False,
            'code': 400,
            'text': "Validation failed.",
            'errors': serializer.errors
        }, status=400)



class VendorBranch(CreateAPIView,RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = branch_serializer
    def post(self,request):

        serializer_objects           = branch_serializer(request.data)                 # convertion of request.data into python native datatype
        json_data                    = JSONRenderer().render(serializer_objects.data)      # rendering the data into json
        stream_data_over_network     = io.BytesIO(json_data)                                 # streaming the data into bytes
        accept_json_stream           = JSONParser().parse(stream_data_over_network)            # prases json data types data


        serializer                   = self.serializer_class(data=accept_json_stream,context={"request":request})

        accept_json_stream           =  request.data
        test_if = SalonBranch.objects.filter(staff_name=accept_json_stream.get('staff_name'))
        if len(test_if) == 1:
            return Response({"status":"this mobileno is already registered with a licence !",})
        user_if = SalonBranch.objects.filter(staff_name=accept_json_stream.get('staff_name'),vendor_name=request.user)
        if len(user_if) == 1:
            return Response({"status":"this mobileno is already registered on this licence !",})
        branch_if  =  SalonBranch.objects.filter(branch_name=accept_json_stream.get('branch_name'),staff_name=accept_json_stream.get('staff_name'),vendor_name=request.user)
        if len(branch_if) == 1:
            return Response({"status":"this branch with this username is already exists !",})
        only_branch_if  =  SalonBranch.objects.filter(branch_name=accept_json_stream.get('branch_name'),vendor_name=request.user)
        if len(only_branch_if) == 1:
            return Response({"status":"this branch is already exists on this licence !",})
        user_profile = SwalookUserProfile.objects.get(mobile_no=str(request.user))
        if user_profile.branch_limit == user_profile.branches_created:
            return Response({
                "status":"this licence is reached its branch limit !",})

        # try:
        #     staff_object = VendorStaff.objects.get(mobile_no=accept_json_stream.get('staff_name'))
        # except Exception as e:
        #     return Response({
        #         "status":f"this number {accept_json_stream.get('staff_name')} is not associated with any staff mobile no",})
        queryset = SalonBranch()



        queryset.branch_name =     accept_json_stream.get('branch_name')
        queryset.staff_name     =     accept_json_stream.get('staff_name')
        queryset.password         =     accept_json_stream.get('password')
        queryset.admin_password      =     accept_json_stream.get('branch_name')[:5]+str(request.user)[:7]
        queryset.staff_url  =  accept_json_stream.get('branch_name')
        queryset.admin_url  =  accept_json_stream.get('branch_name')
        queryset.vendor_name  =  request.user
        queryset.save()

        user_profile.branches_created = user_profile.branches_created + 1
        user_profile.save()



        return Response({
            "status":True,
            "admin_password":queryset.admin_password,


        })


    def get(self,request):
        query_set = SalonBranch.objects.filter(vendor_name=request.user)[::-1]
        serializer_obj = branch_serializer(query_set,many=True)
        return Response({
            "status":True,
            "table_data":serializer_obj.data,

        })


class edit_branch(APIView):
    permission_classes = [IsAuthenticated]

    def put(self,request,):
        id = request.query_params.get('id')

        accept_json_stream           =  request.data

        queryset = SalonBranch.objects.get(id=id)

        queryset.delete()
        queryset = SalonBranch()

        queryset.branch_name    =     accept_json_stream.get('branch_name')
        queryset.staff_name         =     accept_json_stream.get('staff_name')
        queryset.password     =     accept_json_stream.get('password')
        queryset.admin_password  =     accept_json_stream.get('admin_password')
        queryset.staff_url =     accept_json_stream.get('staff_url')
        queryset.admin_url =     accept_json_stream.get('admin_url')
        # queryset.status_pending    = accept_json_stream.get('status_pending')
        # queryset.status_completed =  accept_json_stream.get('status_completed')
        # queryset.status_canceled  =  accept_json_stream.get('status_cancelled')

        queryset.vendor_name = request.user
        queryset.save()

        return Response({
                    'status':True,
                    'code':302,
                    'text':"branch update!"



        },)




class delete_branch(APIView):
    permission_classes = [IsAuthenticated]
    def delete(self,request,):
        id = request.query_params.get('id')
        queryset = SalonBranch.objects.get(id=id)

        queryset.delete()
        user_profile = SwalookUserProfile.objects.get(mobile_no=str(request.user))
        user_profile.branches_created = user_profile.branches_created - 1
        user_profile.save()
        return Response({
            "status":True,
            'code':302,
            "branch_deleted_id":id,

        })


class user_verify(APIView):
    permission_classes = [AllowAny]
    def get(self,request):
        try:
            salon_name = request.query_params.get('salon_name')
            branch_name = request.query_params.get('branch_name')
            sallon_name = SwalookUserProfile.objects.filter(salon_name=salon_name)
            user = User.objects.get(username=sallon_name[0].mobile_no)
            queryset = SalonBranch.objects.get(vendor_name=user,branch_name=branch_name,)


            return Response({
                "status":True,
                'code':302,


            })
        except Exception as e:
            return Response({
                "status":False,
                'code':302,


            })


class present_day_appointment(APIView):
    permission_classes = [IsAuthenticated]

    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)
    def get(self,request):
        branch_name = request.query_params.get('branch_name')
        date = dt.date.today()
        query_set = VendorAppointment.objects.filter(vendor_name=request.user,date=date,vendor_branch_id=branch_name).order_by("booking_time")
        serializer_obj = appointment_serializer(query_set,many=True)
        return Response({

            "status":True,
            "table_data":serializer_obj.data,
        })

class get_specific_appointment(APIView):
    permission_classes = [IsAuthenticated]
    def get(self,request,):
        id = request.query_params.get('id')
        # date = dt.date.today()
        query_set = VendorAppointment.objects.filter(id=id)
        serializer_obj = appointment_serializer(query_set,many=True)
        return Response({

            "status":True,
            "single_appointment_data":serializer_obj.data,
        })





class showendpoint(APIView):
    permission_classes = [AllowAny]
    def get(self,request):
        return Response({
            "status":True,

            "endpoints": ""

        })


import subprocess

class update_files_pull(APIView):
    permission_classes = [AllowAny]
    def get(self,request):

        command = ['git','pull']

        try:

            result = subprocess.run(command, capture_output=True, text=True, check=True)
            output = result.stdout
        except subprocess.CalledProcessError as e:

            output = f"Error: {e.stderr}"
        return Response({
            "server updated" : output,
        })

class restart_server(APIView):
    permission_classes = [AllowAny]
    def get(self,request):

        os.chdir("/root/api_swalook/Swalook-master/")
        command = ['npm','run','build']
        command2 = ['PORT=80','serve','-s','build']



        try:

            result = subprocess.run(command, capture_output=True, text=True, check=True)
            output = result.stdout
            result_ = subprocess.run(command2, capture_output=True, text=True, check=True)
            output_ = result_.stdout
            return Response({
            "server build status" : output,
            "server running" : output_,
            "status": True,
            })
        except subprocess.CalledProcessError as e:

            output = f"Error: {e.stderr}"
            return Response({
            "error":output,
            "status": False,
            })

class get_current_user_profile(APIView):
    permission_classes = [IsAuthenticated]

    def get(self,request,):
        id = request.query_params.get('id')
        data = SwalookUserProfile.objects.get(mobile_no=id)
        serializer_data = user_data_set_serializer(data)
        return Response({
            "status":True,
            "current_user_data":serializer_data.data,

        })

class get_present_day_bill(APIView):
    permission_classes = [IsAuthenticated]

    def get(self,request):
        branch_name = request.query_params.get('branch_name')
        data = VendorInvoice.objects.filter(vendor_name=request.user,vendor_branch=branch_name,date=dt.date.today())
        serializer_data = billing_serializer_get(data,many=True)
        return Response({
            "status":True,
            "current_user_data":serializer_data.data,

        })

class get__bill(APIView):
    permission_classes = [IsAuthenticated]


    def get(self,request,):
        id = request.query_params.get('id')
        data = VendorInvoice.objects.select_related('vendor_customers_profile').get(id=id)
        serializer_data = billing_serializer_get(data)
        return Response({
            "status":True,
            "current_user_data":serializer_data.data,

        })


class render_branch_data(APIView):
    permission_classes = [IsAuthenticated]
    def __init__(self):
        self.cache_key = None
    def dispatch(self, request, *args, **kwargs):
        self.cache_key = f"Vendorbranchbill/{request.user}"
        self.cache_key2 = f"Vendorbranchapp/{request.user}"
        return super().dispatch(request, *args, **kwargs)


    def get(self,request):
        # try:
            branch_name = request.query_params.get('branch_name')
            date = request.query_params.get('date')
            if "%20" in branch_name:
                branch_name =  branch_name.replace("%20", " ")


            main_user = SwalookUserProfile.objects.get(mobile_no=str(request.user))



            # staff = VendorStaff.objects.get(vendor_name=request.user,vendor_branch=salon_branch.branch_name,mobile_no=salon_branch[0].staff_name,)
            inv = VendorInvoice.objects.filter(vendor_name=request.user,vendor_branch_id=branch_name,date=date)
            app = VendorAppointment.objects.filter(vendor_name=request.user,vendor_branch_id=branch_name,date=str(date))
            # stf = VendorStaff.objects.filter(vendor_name=request.user,vendor_branch=salon_branch,date=date)
            # ser = VendorService.objects.filter(vendor_name=request.user,vendor_branch=salon_branch,date=date)

            serializer_data_bill = billing_serializer_get(inv,many=True)
            serializer_data_appo = appointment_serializer(app,many=True)


            return Response({
                "status":True,
                "branch_name":inv[0].vendor_branch,
                "salon_name":main_user.salon_name,

                "invoices": serializer_data_bill.data,
                "appointment": serializer_data_appo.data
                # "services":serializer_data_serv,
                # "staff":serializer_data_staf,


                })


    # except Exception as e:
            #     return Response({
            #     "status":"this branch is deleted by the vendor",


            # })


class ForgotPassword(APIView):
    permission_classes = [AllowAny]
    def __init__(self):
        self.otp = None

    def get(self,request,):
        email = request.query_params.get('email')
        import random as r
        a = r.randint(0,9)
        b = r.randint(0,9)
        c = r.randint(0,9)
        d = r.randint(0,9)
        e = r.randint(0,9)
        f = r.randint(0,9)
        request.session[str(request.user)] = f"{a}{b}{c}{d}{e}{f}"

        # try:
        user = SwalookUserProfile.objects.get(email=email)
        subject = "Swalook - OTP Verification"
        body = f"your 6 digit otp is {request.session.get(str(request.user))}. \n Thank you\n Swalook"
        send_mail(subject,body,'info@swalook.in',[user.email])
        # except Exception:
        #     return Response({
        #     "status":"invalid email-id",
        # })

        return Response({
            "status":True,
        })
    def post(self,request,):
        otp =  request.query_params.get('otp')
        if otp == request.session.get(str(request.user)):
            return Response({
                "status":True,

            })
        else:
            return Response({
                "status":False,
                "message":"Invalid OTP",


            })

class BusniessAnalysiss(APIView):
    permission_classes = [IsAuthenticated]
    def __init__(self):
        self.mon = dt.date.today()




    def get(self,request,):
        pass


class help_desk(CreateAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = HelpDesk_Serializer
    def post(self,request):

        serializer_objects           = HelpDesk_Serializer(request.data)                 # convertion of request.data into python native datatype
        json_data                    = JSONRenderer().render(serializer_objects.data)      # rendering the data into json
        stream_data_over_network     = io.BytesIO(json_data)                                 # streaming the data into bytes
        accept_json_stream           = JSONParser().parse(stream_data_over_network)            # prases json data types data


        serializer                   = HelpDesk_Serializer(data=accept_json_stream,context={'request':request})               # intializing serializer and
        if serializer.is_valid():                                                                   # check if serializer.data is valid
                                                                                    # all the .validate_fieldname in the serializer will call here


            serializer.save()                                                       # the create method of serializer call here

            subject = "Swalook - Query form "
            body = f" {serializer.data}. \n Thank you\n Swalook"
            send_mail(subject,body,'info@swalook.in',["info@swalook.in"])
            return Response({
                "status":True,
                'from mail':'info@swalook.in',
                'to mail':'info@swalook.in',
            })



























class Add_Inventory_Product(CreateAPIView, UpdateAPIView, ListAPIView, DestroyAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = Inventory_Product_Serializer

    def post(self, request, *args, **kwargs):
        branch_name = request.query_params.get('branch_name')
        if not branch_name:
            return Response({"status": False, "text": "Branch name is required."}, status=status.HTTP_400_BAD_REQUEST)

        product_id = request.data.get('product_id')
        product_name = request.data.get('product_name')

        filters = {'user': request.user, 'vendor_branch_id': branch_name}
        valid_1 = VendorInventoryProduct.objects.filter(**filters, product_id=product_id, product_name=product_name).exists()
        valid_2 = VendorInventoryProduct.objects.filter(**filters, product_id=product_id).exists()
        valid_3 = VendorInventoryProduct.objects.filter(**filters, product_name=product_name).exists()

        if valid_1:
            return Response({"status": False, "text": "Product already exists with the same name and ID"}, status=status.HTTP_400_BAD_REQUEST)
        if valid_2:
            return Response({"status": False, "text": "Product already exists with the same ID"}, status=status.HTTP_400_BAD_REQUEST)
        if valid_3:
            return Response({"status": False, "text": "Product already exists with the same name"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.serializer_class(data=request.data, context={'request': request, 'branch_id': branch_name})
        if serializer.is_valid():
            serializer.save()
            return Response({"status": True, "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response({"status": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, *args, **kwargs):
        id = request.query_params.get('id')
        branch_name = request.query_params.get('branch_name')

        if not id or not branch_name:
            return Response({"status": False, "text": "ID and branch name are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            instance = VendorInventoryProduct.objects.get(user=request.user, id=id)
        except ObjectDoesNotExist:
            return Response({"status": False, "text": "Product not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = update_inventory_product_serializer(instance, data=request.data, context={'request': request, 'branch_id': branch_name})
        if serializer.is_valid():
            serializer.save()
            return Response({"status": True, "text": "Data updated"}, status=status.HTTP_200_OK)
        return Response({"status": False, "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, *args, **kwargs):
        id = request.query_params.get('id')
        if not id:
            return Response({"status": False, "text": "ID is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            data_object = VendorInventoryProduct.objects.get(user=request.user, id=id)
            data_object.delete()
            return Response({"status": True, "text": "Product deleted."}, status=status.HTTP_204_NO_CONTENT)
        except ObjectDoesNotExist:
            return Response({"status": False, "text": "Product not found."}, status=status.HTTP_404_NOT_FOUND)

    def list(self, request, *args, **kwargs):
        branch_name = request.query_params.get('branch_name')
        if not branch_name:
            return Response({"status": False, "text": "Branch name is required."}, status=status.HTTP_400_BAD_REQUEST)

        data_objects = VendorInventoryProduct.objects.filter(user=request.user, vendor_branch_id=branch_name).order_by('-id')
        serializer = self.serializer_class(data_objects, many=True)
        return Response({"status": True, "data": serializer.data}, status=status.HTTP_200_OK)















class Bill_Inventory(CreateAPIView,UpdateAPIView,RetrieveAPIView,DestroyAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = Inventory_Product_Invoice_Serializer

    def post(self,request):
        ''' deserialization of register user'''
        branch_name = request.query_params.get('branch_name')
        serializer_objects           = self.serializer_class(request.data)                 # convertion of request.data into python native datatype
        json_data                    = JSONRenderer().render(serializer_objects.data)      # rendering the data into json
        stream_data_over_network     = io.BytesIO(json_data)                                 # streaming the data into bytes
        accept_json_stream           = JSONParser().parse(stream_data_over_network)            # prases json data types data
        ''' passing the json stream data into serializer '''

        serializer                   = self.serializer_class(data=accept_json_stream,context={'request':request,'branch_id':branch_name})               # intializing serializer and
        if serializer.is_valid():                                                                   # check if serializer.data is valid
                                                                                    # all the .validate_fieldname in the serializer will call here
            ''' here the db call happen after accept  '''

            serializer.save()                                                       # the create method of serializer call here
            ''' returning the status and info as response'''

            return Response({
            "status":True,
            "data":serializer.data
            })

    def put(self,request,id):
        pass
    def delete(self,request,id):
        pass





class Vendor_loyality_customer_profile(CreateAPIView,ListAPIView,UpdateAPIView,DestroyAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = VendorCustomerLoyalityProfileSerializer

    def post(self,request):
        ''' deserialization of register user'''
        branch_name = request.query_params.get('branch_name')
        try:
            VendorCustomers.objects.get(user=request.user,mobile_no=request.data.get('mobile_no'))
            return Response({
            "status":False,
            "message":"vendor customer already exists"
            })
        except Exception:




            serializer                   = self.serializer_class(data=request.data,context={'request':request,'branch_id':branch_name})               # intializing serializer and
            if serializer.is_valid():                                                                   # check if serializer.data is valid
                                                                                        # all the .validate_fieldname in the serializer will call here
                ''' here the db call happen after accept  '''

                serializer.save()                                                       # the create method of serializer call here
                ''' returning the status and info as response'''

                return Response({
                "status":True,
                # "data":serializer.data
                })
            else:
                return Response({
                "status":False,

                })

    def list(self,request,):
        branch_name = request.query_params.get('branch_name')
        if "%20" in branch_name:
            branch_name =  branch_name.replace("%20", " ")

        data_object = VendorCustomers.objects.select_related('loyality_profile').filter(user=request.user)[::-1]
        serializer_obj  =  VendorCustomerLoyalityProfileSerializer_get(data_object,many=True)

        return Response({
            "status":True,
            "data":serializer_obj.data
        })


    def put(self,request,):
        id = request.query_params.get('id')
        branch_name = request.query_params.get('branch_name')
        ''' deserialization of register user'''
        serializer_objects           = loyality_customer_update_serializer(request.data)                 # convertion of request.data into python native datatype
        json_data                    = JSONRenderer().render(serializer_objects.data)      # rendering the data into json
        stream_data_over_network     = io.BytesIO(json_data)                                 # streaming the data into bytes
        accept_json_stream           = JSONParser().parse(stream_data_over_network)            # prases json data types data
        ''' passing the json stream data into serializer '''

        serializer                   = loyality_customer_update_serializer(data=accept_json_stream,context={'request':request,'id':id,'branch_id':branch_name})               # intializing serializer and
        if serializer.is_valid():                                                                   # check if serializer.data is valid
                                                                                    # all the .validate_fieldname in the serializer will call here
            ''' here the db call happen after accept  '''

            serializer.save()                                                       # the update method of serializer call here
            ''' returning the status and info as response'''

            return Response({
            "status":True,

            })
    def delete(self,request,):
        id = request.query_params.get('id')
        obj = VendorCustomers.objects.get(id=id)
        clp = VendorCustomerLoyalityPoints.objects.get(id=obj.loyality_profile.id)
        obj.delete()
        clp.delete()

        return Response({
            "status":True,
            "txt":f"object deleted of this id {id}"
            })

class Get_Profile(ListAPIView):

    def list(self,request):
        branch_name = request.query_params.get('branch_name')
        mobile_no = request.query_params.get('mobile_no')
        if "%20" in branch_name:
            branch_name =  branch_name.replace("%20", " ")

        data_object = VendorCustomers.objects.filter(user=request.user,vendor_branch_id=branch_name,mobile_no=mobile_no)
        serializer_obj  =  VendorCustomerLoyalityProfileSerializer_get(data_object,many=True)

        return Response({
            "status":True,
            "data":serializer_obj.data
        })


class Vendor_loyality_type_add(CreateAPIView,UpdateAPIView,DestroyAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = VendorLoyalityTypeSerializer

    def post(self,request):
        branch_name = request.query_params.get('branch_name')
        try:
            VendorLoyalityProgramTypes.objects.get(user=request.user,vendor_branch_id=branch_name,program_type=request.data.get('json_data')[0].get('type'))
            return Response({
            "status":False,
            "txt":"loyality program type already exists!"
            })

        except Exception:

            serializer_objects           = self.serializer_class(request.data)                 # convertion of request.data into python native datatype
            json_data                    = JSONRenderer().render(serializer_objects.data)      # rendering the data into json
            stream_data_over_network     = io.BytesIO(json_data)                                 # streaming the data into bytes
            accept_json_stream           = JSONParser().parse(stream_data_over_network)            # prases json data types data
            ''' passing the json stream data into serializer '''

            serializer                   = self.serializer_class(data=accept_json_stream,context={'request':request,'branch_id':branch_name})               # intializing serializer and
            if serializer.is_valid():                                                                   # check if serializer.data is valid
                                                                                        # all the .validate_fieldname in the serializer will call here
                ''' here the db call happen after accept  '''

                serializer.save()                                                       # the create method of serializer call here
                ''' returning the status and info as response'''

                return Response({
                "status":True,
                # "data":serializer.data
                })

    def put(self,request,):
        id = request.query_params.get('id')
        branch_name = request.query_params.get('branch_name')
        serializer_objects           = Vendor_Type_Loyality_Update_Serializer(request.data)                 # convertion of request.data into python native datatype
        json_data                    = JSONRenderer().render(serializer_objects.data)      # rendering the data into json
        stream_data_over_network     = io.BytesIO(json_data)                                 # streaming the data into bytes
        accept_json_stream           = JSONParser().parse(stream_data_over_network)            # prases json data types data
        ''' passing the json stream data into serializer '''

        serializer                   = Vendor_Type_Loyality_Update_Serializer(data=accept_json_stream,context={'request':request,'id':id,'branch_id':branch_name})               # intializing serializer and
        if serializer.is_valid():                                                                   # check if serializer.data is valid
                                                                                    # all the .validate_fieldname in the serializer will call here
            ''' here the db call happen after accept  '''

            serializer.save()                                                       # the update method of serializer call here
            ''' returning the status and info as response'''

            return Response({
            "status":True,
            "txt":"loyality type updated"
            })
    def delete(self,request,):
        id = request.query_params.get('id')
        obj = VendorLoyalityProgramTypes.objects.get(id=id)
        obj.delete()
        return Response({
            "status":True,
            "txt":f"object deleted of this id {id}"
            })

class Vendor_loyality_type_add_get(ListAPIView):
    def list(self,request,):
        branch_name = request.query_params.get('branch_name')
        if "%20" in branch_name:
            branch_name =  branch_name.replace("%20", " ")

        data_object = VendorLoyalityProgramTypes.objects.filter(user=request.user,vendor_branch_id=branch_name,)[::-1]
        serializer_obj  = VendorLoyalityTypeSerializer_get(data_object,many=True)

        return Response({
            "status":True,
            "data":serializer_obj.data
        })

class Check_Loyality_Customer_exists(APIView):
    def get(self,request):
        branch_name = request.query_params.get('branch_name')
        customer_mobile_no= request.query_params.get('customer_mobile_no')

        if "%20" in branch_name:
            branch_name =  branch_name.replace("%20", " ")
        try:
            obj = VendorCustomers.objects.get(user=request.user,vendor_branch_id=branch_name,mobile_no=customer_mobile_no)
            serializer_obj  = VendorCustomerLoyalityProfileSerializer(obj)
            return Response({
                "status":True,
                "membership_type":obj.membership_type.program_type,
                "points":obj.loyality_profile.current_customer_points


            })
        except Exception:
            return Response({
            "status":False,
            "data":"user does not exists"
        })

class Inventory_Products_get(APIView):
    def get(self,request,):
        branch_name = request.query_params.get('branch_name')
        if "%20" in branch_name:
            branch_name =  branch_name.replace("%20", " ")
        product_obj = VendorInventoryProduct.objects.filter(user=request.user,vendor_branch_id=branch_name).values('id','product_name')
        return Response({
            "status":True,
            "data":list(product_obj)
        })
class MembershipTypesLoyality_get(APIView):
    def get(self,request,):
        branch_name = request.query_params.get('branch_name')
        if "%20" in branch_name:
            branch_name =  branch_name.replace("%20", " ")
        product_obj = VendorLoyalityProgramTypes.objects.filter(user=request.user,vendor_branch_id=branch_name).values('program_type')
        return Response({
            "status":True,
            "data":list(product_obj)
        })



class update_minimum_amount(CreateAPIView,RetrieveAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = update_minuimum_amount_serializer
    def post(self,request):
        ''' deserialization of register user'''
        branch_name = request.query_params.get('branch_name')
        serializer_objects           = self.serializer_class(request.data)                 # convertion of request.data into python native datatype
        json_data                    = JSONRenderer().render(serializer_objects.data)      # rendering the data into json
        stream_data_over_network     = io.BytesIO(json_data)                                 # streaming the data into bytes
        accept_json_stream           = JSONParser().parse(stream_data_over_network)            # prases json data types data
        ''' passing the json stream data into serializer '''

        serializer                   = self.serializer_class(data=accept_json_stream,context={'request':request,'branch_id':branch_name})               # intializing serializer and
        if serializer.is_valid():                                                                   # check if serializer.data is valid
                                                                                    # all the .validate_fieldname in the serializer will call here
            ''' here the db call happen after accept  '''

            serializer.save()                                                       # the create method of serializer call here
            ''' returning the status and info as response'''

            return Response({
            "status":True,
            # "data":serializer.data
            })

    def get(self,request,):
        branch_name = request.query_params.get('branch_name')
        obj_user = SalonBranch.objects.get(id=branch_name)
        return Response({
            "status":True,
            "data":obj_user.minimum_purchase_loyality

            })

class vendor_staff(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = staff_serializer

    def __init__(self, **kwargs):
        self.cache_key = None
        super().__init__(**kwargs)

    # def dispatch(self, request, *args, **kwargs):
    #     self.cache_key = f"VendorBilling/{request.user.id}"
    #     return super().dispatch(request, *args, **kwargs)
    @transaction.atomic
    def post(self, request):
        branch_name = request.query_params.get('branch_name')
        if not branch_name:
            return Response({
                'success': False,
                'status_code': status.HTTP_400_BAD_REQUEST,
                'error': {
                    'code': 'Bad Request',
                    'message': 'branch_name parameter is missing!'
                },
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)
        serializer = self.serializer_class(data=request.data, context={'request': request, 'branch_id': branch_name})

        if serializer.is_valid():
            serializer.save()
            return Response({
                "status": True,

                "message": "staff added successfully."
            }, status=status.HTTP_201_CREATED)

        return Response({
            "status": False,
            "errors": serializer.errors,
            "message": "Failed to add staff."
        }, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        branch_name = request.query_params.get('branch_name')
        if not branch_name:
            return Response({
                'success': False,
                'status_code': status.HTTP_400_BAD_REQUEST,
                'error': {
                    'code': 'Bad Request',
                    'message': 'branch_name parameter is missing!'
                },
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)


        queryset = VendorStaff.objects.filter(
            vendor_name=request.user,
            vendor_branch_id=branch_name
        ).order_by('-id')

        serializer = self.serializer_class(queryset, many=True)




        return Response({
            "status": True,
            "table_data": serializer.data,

            "message": "Staff records retrieved successfully."
        }, status=status.HTTP_200_OK)


    @transaction.atomic
    def put(self, request):
        # Extract query parameters
        staff_id = request.query_params.get('id')
        branch_name = request.query_params.get('branch_name', "").replace("%20", " ")

        if not staff_id:
            return Response({
                'status': False,
                'error': 'staff ID are required.'
            }, status=400)




        try:
            staff = VendorStaff.objects.get(id=staff_id, vendor_name=request.user)
        except VendorStaff.DoesNotExist:
            raise NotFound('Staff not found.')


        data = request.data.copy()
        data['vendor_branch_id'] = branch_name
        data['date'] = dt.date.today()


        serializer =  self.serializer_class(staff, data=data, partial=True, context={"request": request,"branch_id":branch_name,"staff_id":staff_id})
        if serializer.is_valid():
            serializer.save()
            return Response({
                'status': True,
                'message': "staff updated successfully.",
                'data': serializer.data,
            }, status=200)
        else:
            return Response({
                'status': False,
                'errors': serializer.errors
            }, status=400)







    def delete(self,request,):
        id = request.query_params.get('id')

        clp = VendorStaff.objects.get(id=id)

        clp.delete()

        return Response({
            "status":True,
            "txt":f"object deleted of this id {id}"
            })



class vendor_staff_setting_slabs(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = staff_update_earning_deduction_serializer

    def __init__(self, **kwargs):
        self.cache_key = None
        super().__init__(**kwargs)

    # def dispatch(self, request, *args, **kwargs):
    #     self.cache_key = f"VendorBilling/{request.user.id}"
    #     return super().dispatch(request, *args, **kwargs)
    @transaction.atomic
    def post(self, request):
        branch_name = request.query_params.get('branch_name')
        if not branch_name:
            return Response({
                'success': False,
                'status_code': status.HTTP_400_BAD_REQUEST,
                'error': {
                    'code': 'Bad Request',
                    'message': 'branch_name parameter is missing!'
                },
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)
        s_s = StaffSetting.objects.filter(vendor_name=request.user)
        s_s_s = StaffSettingSlab.objects.filter(vendor_name=request.user)
        if len(s_s) != 0:
            if len(s_s_s) != 0:
                s_s.delete()
                s_s_s.delete()
        serializer = self.serializer_class(data=request.data, context={'request': request, 'branch_id': branch_name})

        if serializer.is_valid():
            data_validate = serializer.save()

            return Response({
                "status": True,

                "message": "staff setting added successfully.",
                "data":data_validate
            }, status=status.HTTP_201_CREATED)

        return Response({
            "status": False,
            "errors": serializer.errors,
            "message": "Failed to add staff."
        }, status=status.HTTP_400_BAD_REQUEST)




class vendor_staff_attendance(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = staff_attendance_serializer

    def __init__(self, **kwargs):
        self.cache_key = None
        super().__init__(**kwargs)


    @transaction.atomic
    def post(self, request):
        branch_name = request.query_params.get('branch_name')

        if not branch_name:
            return Response({
                'success': False,
                'status_code': status.HTTP_400_BAD_REQUEST,
                'error': {
                    'code': 'Bad Request',
                    'message': 'branch_name parameter is missing!'
                },
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

        for i in request.data.get('json_data'):
            try:
                VendorStaffAttendance.objects.get(date=i.get('date'),staff_id=request.query_params.get('staff_id'))
                return Response({
                    "status": True,

                    "message": "staff attendance already exists"
                })
            except Exception:
                pass
        serializer = self.serializer_class(data=request.data, context={'request': request, 'branch_id': branch_name,})


        serializer.create(validated_data=request.data)
        return Response({
                "status": True,

                "message": "staff attendance added successfully."
        }, status=status.HTTP_201_CREATED)



    def get(self, request):
        branch_name = request.query_params.get('branch_name')
        if not branch_name:
            return Response({
                'success': False,
                'status_code': status.HTTP_400_BAD_REQUEST,
                'error': {
                    'code': 'Bad Request',
                    'message': 'branch_name parameter is missing!'
                },
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)





        staff = VendorStaff.objects.filter(vendor_name=request.user)


        current_date = dt.date.today()


        attendance_queryset = VendorStaffAttendance.objects.filter(
            vendor_name=request.user,
            vendor_branch_id=branch_name,
            of_month=current_date.month,
            year=current_date.year,
        ).values(
            "staff_id",
            "attend",
            "leave",
            "date"
        )


        attendance_data = {}
        for record in attendance_queryset:
            staff_id = record["staff_id"]
            if staff_id not in attendance_data:
                attendance_data[staff_id] = {
                    "present_dates": [],
                    "leave_dates": [],
                    "number_of_days_present": 0,
                    "no_of_days_absent": 0,
                }
            if record["attend"]:
                attendance_data[staff_id]["present_dates"].append(record["date"])
                attendance_data[staff_id]["number_of_days_present"] += 1
            if record["leave"]:
                attendance_data[staff_id]["leave_dates"].append(record["date"])
                attendance_data[staff_id]["no_of_days_absent"] += 1


        all_staff_attendance = {}
        for staff_member in staff:
            staff_id = staff_member.id
            data = attendance_data.get(staff_id, {
                "present_dates": [],
                "leave_dates": [],
                "number_of_days_present": 0,
                "no_of_days_absent": 0,
            })
            all_staff_attendance[staff_member.mobile_no] = {
                "id": staff_id,
                "month": current_date.month,
                **data
            }


        staff_settings_obj = StaffSetting.objects.filter(
            vendor_name=request.user,
            month=current_date.month
        ).first()

        return Response({
            "status": True,
            "table_data": all_staff_attendance,
            "current_month_days": staff_settings_obj.number_of_working_days if staff_settings_obj else 0,
            "message": "Attendance records retrieved successfully."
        }, status=status.HTTP_200_OK)


    def put(self,request):
        pass
    def delete(self,request):
        pass

class salary_disburse(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = staff_salary_serializer

    def __init__(self, **kwargs):
        self.cache_key = None


    # def dispatch(self, request, *args, **kwargs):
    #     self.cache_key = f"VendorBilling/{request.user.id}"
    #     return super().dispatch(request, *args, **kwargs)

    def get(self,request):
        id = request.query_params.get('id')
        staff_attendance = VendorStaffAttendance.objects.filter(staff_id=id,of_month=dt.date.today().month)
        staff_setting = StaffSetting.objects.select_related('vendor_name').get(vendor_name=request.user,month=dt.date.today().month)
        staff_slab = StaffSettingSlab.objects.select_related('vendor_name').filter(vendor_name=request.user).values_list('staff_target_business', 'staff_slab').order_by('-staff_target_business')

        def calculate_commission(business_amount,slabs):
                commission = 0



                for threshold, percentage in slabs:
                    if business_amount > int( threshold):
                        extra_amount = int(business_amount) - int(threshold)
                        commission += (extra_amount * float(percentage)) / 100


                return commission
        commission = calculate_commission(int(staff_attendance[0].staff.business_of_the_current_month),staff_slab)
        staff_salary = StaffSalary()

        staff_salary.of_month = dt.date.today().month
        staff_salary.salary_payble_amount = (int(staff_attendance[0].staff.staff_salary_monthly) / staff_setting.number_of_working_days ) * int(staff_attendance.count())
        staff_salary.salary_payble_amount = staff_salary.salary_payble_amount + commission
        staff_salary.staff_id = id
        staff_salary.year = dt.date.today().year
        staff_salary.save()


        serializer = staff_salary_serializer(staff_salary)

        if commission == 0:
            commission = int(staff_salary.salary_payble_amount)



        return Response({
            "status": True,
            "id":id,
            "net_payble_amount":int(staff_salary.salary_payble_amount),
            "no_of_working_days":staff_attendance.count(),

            "earning":commission,


            "message": "staff salary records retrieved successfully."
        }, status=status.HTTP_200_OK)




class Sales_Per_Customer(APIView):
    permission_classes = [IsAuthenticated]

    # billing_data = Billing.objects.filter(month=month, year=year).values('customer', 'week').annotate(weekly_bills=Count('id')).order_by('customer', 'week')
    def get(self,request):
        month = request.query_params.get('month')
        year = request.query_params.get('year')
        week = request.query_params.get('week')
        branch_name = request.query_params.get('branch_name')
        billing_data_weekly_customer = VendorInvoice.objects.filter(vendor_name=request.user,vendor_branch_id=branch_name,year=year,month=month,week=week).values('vendor_customers_profile__mobile_no').annotate(weekly_total=Sum('grand_total')).order_by('vendor_customers_profile__mobile_no', 'week')

        return Response({
            "data":billing_data_weekly_customer,
            # "data1":billing_data_monthly_customer,
            # "data2":billing_data_weekly_month,
            # "data3":billing_data_monthly_year,
            })

class Sales_Per_Customer_monthly(APIView):
    permission_classes = [IsAuthenticated]

    # billing_data = Billing.objects.filter(month=month, year=year).values('customer', 'week').annotate(weekly_bills=Count('id')).order_by('customer', 'week')
    def get(self,request):
        month = request.query_params.get('month')
        year = request.query_params.get('year')
        branch_name = request.query_params.get('branch_name')

        billing_data_monthly_customer = VendorInvoice.objects.filter(vendor_name=request.user,vendor_branch_id=branch_name,year=year,month=month,).values('vendor_customers_profile__mobile_no').annotate(weekly_total=Sum('grand_total')).order_by('vendor_customers_profile__mobile_no',)

        return Response({
            # "data":billing_data_weekly_customer,
            "data":billing_data_monthly_customer,
            # "data2":billing_data_weekly_month,
            # "data3":billing_data_monthly_year,
            })


class Sales_in_a_month(APIView):
    permission_classes = [IsAuthenticated]


    # billing_data = Billing.objects.filter(month=month, year=year).values('customer', 'week').annotate(weekly_bills=Count('id')).order_by('customer', 'week')
    def get(self,request):
        month = request.query_params.get('month')
        year = request.query_params.get('year')
        # week = request.query_params.get('week')
        branch_name = request.query_params.get('branch_name')
        billing_data_weekly_month = VendorInvoice.objects.filter(vendor_name=request.user,vendor_branch_id=branch_name,month=month, year=year).values('week').annotate(weekly_total=Sum('grand_total')).order_by('week')

        return Response({
            # "data":billing_data_weekly_customer,
            # "data1":billing_data_monthly_customer,
            "data2":billing_data_weekly_month,
            # "data3":billing_data_monthly_year,
            })


class Sales_in_a_year(APIView):
    permission_classes = [IsAuthenticated]

    # billing_data = Billing.objects.filter(month=month, year=year).values('customer', 'week').annotate(weekly_bills=Count('id')).order_by('customer', 'week')
    def get(self,request):

        year = request.query_params.get('year')
        branch_name = request.query_params.get('branch_name')
        billing_data_monthly_year = VendorInvoice.objects.filter(vendor_name=request.user,vendor_branch_id=branch_name,year=year).values('month').annotate(monthly_total=Sum('grand_total')).order_by('month')

        return Response({
            # "data":billing_data_weekly_customer,
            # "data1":billing_data_monthly_customer,
            # "data2":billing_data_weekly_month,
            "data":billing_data_monthly_year,
            })


class Sales_in_a_week(APIView):
    permission_classes = [IsAuthenticated]

    # billing_data = Billing.objects.filter(month=month, year=year).values('customer', 'week').annotate(weekly_bills=Count('id')).order_by('customer', 'week')
    def get(self,request):

        week = request.query_params.get('week')
        branch_name = request.query_params.get('branch_name')

        sales_by_day = VendorInvoice.objects.filter(vendor_name=request.user,vendor_branch_id=branch_name,week=week,).annotate(
            day_of_week=ExtractWeekDay('date')
        ).values(
            'day_of_week'
        ).annotate(
            total_sales=Sum('grand_total')
        ).order_by('day_of_week')







        return Response({

            "data":sales_by_day,
            })


class Sales_in_a_day_by_customer(APIView):
    permission_classes = [IsAuthenticated]

    # billing_data = Billing.objects.filter(month=month, year=year).values('customer', 'week').annotate(weekly_bills=Count('id')).order_by('customer', 'week')
    def get(self,request):
        branch_name = request.query_params.get('branch_name')


        billing_data_monthly_year = VendorInvoice.objects.filter(vendor_name=request.user,vendor_branch_id=branch_name,date=dt.date.today()).annotate(daily_total=Sum('grand_total'))

        return Response({
            # "data":billing_data_weekly_customer,
            # "data1":billing_data_monthly_customer,
            # "data2":billing_data_weekly_month,
            "data":billing_data_monthly_year,
            })

class Sales_in_a_day_by_customer_time(APIView):
    permission_classes = [IsAuthenticated]

    # billing_data = Billing.objects.filter(month=month, year=year).values('customer', 'week').annotate(weekly_bills=Count('id')).order_by('customer', 'week')
    def get(self,request):

        start_time = request.query_params.get('start_time')
        end_time = request.query_params.get('end_time')

        billing_data_monthly_year = VendorInvoice.objects.filter(vendor_name=request.user,date=dt.date.today(),timestamp__range=(start_time, end_time))

        billing_data_monthly_year_time = billing_serializer_get(billing_data_monthly_year,many=True)
        return Response({
            # "data":billing_data_weekly_customer,
            # "data1":billing_data_monthly_customer,
            # "data2":billing_data_weekly_month,
            "data":billing_data_monthly_year_time.data,
            })



class service_analysis(APIView):
    permission_classes = [IsAuthenticated]

    def get(self,request):
        from collections import defaultdict
        import json

        selected_week = request.query_params.get('week')
        selected_year = request.query_params.get('year')
        selected_month = request.query_params.get('month')
        branch_name = request.query_params.get('branch_name')


        weekly_invoices = VendorInvoice.objects.filter(vendor_name=request.user,week=selected_week,month=selected_month, year=selected_year)


        total_amount = 0
        total_services_count = 0
        services_list = defaultdict(int)


        for invoice in weekly_invoices:
            services = json.loads(invoice.services) if isinstance(invoice.services, str) else invoice.services
            for service in services:
                if service['Description'] == 'None':
                    pass
                else:

                    total_amount += service['Total_amount']
                    total_services_count += 1
                    services_list[service['Description']] += 1

        weekly_average = total_amount / total_services_count if total_services_count > 0 else 0



        response_data = {
            "week": selected_week,
            "month": selected_month,
            "year": selected_year,
            "total_amount": total_amount,
            "average_per_service": weekly_average,
            "services_list": dict(services_list)
        }
        return Response({"data":response_data})

class top5_header_staff_revenue(APIView):
    permission_classes = [IsAuthenticated]
    def get(self,request):
        from django.utils.timezone import now
        from django.db.models import Sum
        branch_name = request.query_params.get('branch_name')

        current_date = now().date()
        invoices_today_count = VendorInvoice.objects.filter(date=current_date,vendor_name=request.user,vendor_branch_id=branch_name).count()
        appointmet_today_count = VendorAppointment.objects.filter(vendor_name=request.user,vendor_branch_id=branch_name,date=current_date).count()

        revenue_today = VendorInvoice.objects.filter(vendor_name=request.user,date=current_date,vendor_branch_id=branch_name).aggregate(
            total_revenue=Sum('grand_total')
        )['total_revenue'] or 0
        from django.db.models import Count

        m = dt.date.today().month
        y= dt.date.today().year
        bills_by_staff = VendorInvoice.objects.filter(vendor_name=request.user,vendor_branch_id=branch_name,date=current_date).values('service_by').annotate(
            total_revenue=Sum('grand_total'),
            total_invoices=Count('id')
        ).order_by('-total_revenue')
        bills_by_staff_a = VendorInvoice.objects.filter(vendor_name=request.user,vendor_branch_id=branch_name,month=m,year=y).values('service_by').annotate(
            total_revenue=Sum('grand_total'),
            total_invoices=Count('id')
        ).order_by('-total_revenue')
        bills_by_staff_b = VendorInvoice.objects.filter(vendor_name=request.user,vendor_branch_id=branch_name,year=y).values('service_by').annotate(
            total_revenue=Sum('grand_total'),
            total_invoices=Count('id')
        ).order_by('-total_revenue')

        from django.db.models import Sum
        from django.db.models.functions import TruncMonth


        bills_by_month_and_payment = VendorInvoice.objects.filter(vendor_name=request.user,vendor_branch_id=branch_name).annotate(
            month_is=TruncMonth('date')
        ).values('month', 'mode_of_payment').annotate(
            total_revenue=Sum('grand_total')
        ).order_by('month', '-total_revenue')
        from django.utils.timezone import now, timedelta
        from django.db.models import Sum

        # Calculate the previous day's date
        previous_day = now().date() - timedelta(days=1)

        # Get total revenue for the previous day
        previous_day_revenue = VendorInvoice.objects.filter(vendor_name=request.user,vendor_branch_id=branch_name,date=previous_day).aggregate(
            total_revenue=Sum('grand_total')
        )['total_revenue'] or 0  # Default to 0 if no invoices


        return Response({
            "staff_data":bills_by_staff,
            "staff_data_1":bills_by_staff_a,
            "staff_data_2":bills_by_staff_b,
            "today_no_of_invoices":invoices_today_count,
            "today_revenue":revenue_today,
            "previous_day_rev":previous_day_revenue,
            "mode_of_payment":bills_by_month_and_payment,
            "today_no_of_app":appointmet_today_count,

            })



class GetCustomerBillAppDetails(APIView):
    permission_classes = [IsAuthenticated]
    # permission_classes = [AllowAny]


    def get(self, request):
        mobile_no = request.query_params.get('mobile_no')
        branch_name = request.query_params.get('branch_name')

        if not mobile_no:
            return Response({
                "status": False,
                "message": "Mobile number is required."
            }, status=400)
        if not branch_name:
            return Response({
                "status": False,
                "message": "Branch_name is required."
            }, status=400)


        appointments_all = VendorAppointment.objects.filter(mobile_no=mobile_no, vendor_name=request.user,vendor_branch_id=branch_name)
        # invoice_all = VendorInvoice.objects.filter(mobile_no=mobile_no, vendor_name=request.user)
        invoice_all = VendorInvoice.objects.filter(
            mobile_no=mobile_no, vendor_name=request.user,vendor_branch_id=branch_name
            
        ).select_related(
            'vendor_customers_profile__loyality_profile'
        )

        if invoice_all.exists():
            customer_name = invoice_all[0].customer_name
            customer_email = invoice_all[0].email
            try:
                customer_dob = invoice_all[0].vendor_customers_profile.d_o_b
                customer_doa = invoice_all[0].vendor_customers_profile.d_o_a
            except Exception:
                customer_dob = ""
                customer_doa = ""

            # customer_points = invoice_all[0].vendor_customers_profile.loyality_profile.current_customer_points
        else:
            return Response({
                "status": False,
                "message": "No invoices found for this customer."
            }, status=404)


        count_1 = appointments_all.count()
        count_2 = invoice_all.count()
        total_billing_amount = invoice_all.aggregate(total=Sum('grand_total'))['total']


        appointment_data = appointment_serializer(appointments_all, many=True).data
        invoice_data = billing_serializer_get(invoice_all, many=True).data

        return Response({
            "status": True,
            "total_appointment": count_1,
            "total_invoices": count_2,
            "previous_appointments": appointment_data,
            "previous_invoices": invoice_data,
            "customer_name": customer_name,
            "customer_mobile_no": mobile_no,
            "customer_email": customer_email,
            "customer_dob": customer_dob,
            "customer_doa": customer_doa,
            # "customer_loyality_points": customer_points,  # Uncomment if needed
            "total_billing_amount": total_billing_amount,
        })





# @receiver(post_save, sender=VendorService)
# def clear_cache_on_save(sender, instance, created, **kwargs,):
#     print("clearing cache on save")
#     cache.delete(f"VendorServices/{instance.user}")
#     cache.delete(f"VendorServicesTable/{instance.user}")
class abc_123(APIView):
    permission_classes = [AllowAny]

    def get(self,request):



        services_dict = {
            "Hair Trimming Ladies": 200,
            "Haircut Ladies": 400,
            "Haircut baby (Below 6 years)": 200,
            "Haircut Gents": 200,
            "Beard Trimming": 100,
            "Face Shave": 100,
            "Regular head massage": 500,
            "Moroccan oil head massage": 600,
            "Root touch up ammonia": 3000,
            "Root touch up ammonia free": 4000,
            "Global hair colour ammonia": 8000,
            "Global hair colour ammonia free": 8000,
            "Global hair colour gents": 3000,
            "Global hair colour ombre": 8000,
            "Global hair colour balayage": 8000,
            "Hair highlights per streak": 300,
            "Hair straightening shoulder": 3000,
            "Hair straightening mid back": 4000,
            "Hair straightening waist": 5000,
            "Hair straightening gents": 2000,
            "Hair smoothening shoulder": 3000,
            "Hair smoothening mid back": 5000,
            "Hair smoothening waist": 6000,
            "Hair smoothening gents": 2000,
            "Rebonding shoulder": 3000,
            "Rebonding mid back": 6000,
            "Rebonding waist": 7000,
            "Rebonding gents": 2000,
            "Nanoplastia treatment shoulder": 6000,
            "Nanoplastia treatment mid back": 8000,
            "Nanoplastia treatment waist": 10000,
            "Botox Treatment shoulder": 4500,
            "Botox Treatment mid back": 6000,
            "Botox Treatment waist": 8000,
            "Keratin Treatment shoulder": 3000,
            "Keratin Treatment mid back": 6000,
            "Keratin Treatment waist": 7000,
            "Keratin Treatment gents": 2000,
            "Hairspa anti dandruff trt shoulder": 1000,
            "Hairspa anti dandruff trt midback": 1500,
            "Hairspa anti dandruff trt waist": 1700,
            "Hairspa anti dandruff trt gents": 1000,
            "Hairspa anti hairfall trt shoulder": 1000,
            "Hairspa anti hairfall trt midback": 1500,
            "Hairspa anti hairfall trt waist": 1700,
            "Hairspa anti hairfall trt gents": 1000,
            "Luxury keratin spa": 2000,
            "Regular spa shoulder": 700,
            "Regular spa mid back": 1500,
            "Regular spa waist": 2000,
            "Regular spa gents": 500,
            "Iluvia Hair Therapy": 2500,
            "PH luxury hair Treatment": 2500,
            "Schwarzkopf Fibre Clinic Treatment": 3000,
            "Schwarzkopf Fibre Plex Treatment": 3000,
            "Temporary straightening": 600,
            "Temporary tong curling": 700,
            "Hairwash and blow-dry": 500,
            "Waxing full arms": 700,
            "Waxing half legs": 700,
            "Waxing full legs": 1000,
            "Waxing underarms": 400,
            "Waxing full body": 3500,
            "Waxing Brazilian": 2100,
            "Face": 500,
            "Upper lip wax": 60,
            "Chin wax": 60,
            "Sidelocks wax": 100,
            "Aloe vera pedicure": 900,
            "Strawberry pedicure": 900,
            "Rose pedicure": 900,
            "Chocolate pedicure": 900,
            "Dead Sea anti tan spa pedicure": 1300,
            "Candle spa pedicure": 1500,
            "Luxury crystal spa pedicure": 1500,
            "Aloe vera manicure": 700,
            "Strawberry manicure": 700,
            "Rose manicure": 700,
            "Chocolate manicure": 700,
            "Dead Sea anti tan spa manicure": 1300,
            "Candle spa manicure": 1300,
            "Luxury crystal spa manicure": 1200,
            "Aroma foot therapy": 800,
            "Aroma hand therapy": 700,
            "Eyebrows threading": 30,
            "Upper lip threading": 30,
            "Chin threading": 30,
            "Forehead threading": 30,
            "Sidelocks threading": 60,
            "Nose piercing": 250,
            "Per ear piercing": 250,
            "Puravitals facial": 1200,
            "Hydravitals facial": 1200,
            "DeTAN skin brightening facial": 1900,
            "Preservita Marmalade facial": 1900,
            "Depigmentation programme": 1900,
            "Goldsheen facial": 2000,
            "4 layers advanced skin whitening": 2900,
            "4 layers advanced anti ageing": 3000,
            "Bridal Gold Ultimo Treatment": 4000,
            "O3+ brightening all skin types": 3500,
            "O3+ seaweed oil skin": 3500,
            "O3+ Bridal glow": 3800,
            "JC Advanced hydrating programme": 1990,
            "JC Pro collagen firming programme": 2300,
            "JC Vit C Brightening programme": 2500,
            "JC Anti acne purifying programme": 2500,
            "JC Brilliance whitening detox programme": 3100,
            "JC Algae mask": 700,
            "Urban men antioxidant programme": 2500,
            "Raaga regular facial": 1100,
            "Raaga anti ageing facial": 1300,
            "Raaga fairness facial": 1400,
            "Raaga anti acne facial": 1500,
            "Raaga gold facial": 1800,
            "Raaga platinum facial": 2000,
            "Regular Cleanup": 700,
            "JC Cleanup": 850,
            "Luxury full body skin polishing": 4000,
            "Detan Face": 400,
            "Dean neck and blouse line": 300,
            "Detan face and neck": 500,
            "Detan full arms": 600,
            "Detan Half legs": 700,
            "Underarm skin polishing": 300,
            "Bridal package comprehensive": 12500,
            "Bridal Package groom": 6500,
        }


        # user = User.objects.get(username="8876548923")
        # d = VendorService.objects.filter(user=user)
        # d.delete()

        # services = [VendorService(service=servi,service_duration="0",service_price=services_dict.get(servi),user=user) for servi in services_dict.keys() if services_dict.get(servi) ]
        # VendorService.objects.bulk_create(services)





        return Response({"done":"done"})




        # raise ValueError("This is a custom error to test email logging.")
class expense_category(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = VendorExpenseCategorySerializer

    def __init__(self, **kwargs):
        self.cache_key = None
        super().__init__(**kwargs)


    @transaction.atomic
    def post(self, request):
        branch_name = request.query_params.get('branch_name')

        if not branch_name:
            return Response({
                'success': False,
                'status_code': status.HTTP_400_BAD_REQUEST,
                'error': {
                    'code': 'Bad Request',
                    'message': 'branch_name parameter is missing!'
                },
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)



        serializer = self.serializer_class(data=request.data, context={'request': request, 'branch_id': branch_name,})


        serializer.create(validated_data=request.data)
        return Response({
                "status": True,

                "message": "Vendor Expense category Added Succesfully"
        }, status=status.HTTP_201_CREATED)

    def get(self, request):
        branch_name = request.query_params.get('branch_name')
        if not branch_name:
            return Response({
                'success': False,
                'status_code': status.HTTP_400_BAD_REQUEST,
                'error': {
                    'code': 'Bad Request',
                    'message': 'branch_name parameter is missing!'
                },
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)


        data = VendorExpenseCategory.objects.filter(user=request.user,)
        serializer = self.serializer_class(data,many=True)





        return Response({
            "status": True,
            "data":serializer.data

        }, status=status.HTTP_200_OK)

class expense_management(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = VendorExpenseSerializer

    def __init__(self, **kwargs):
        self.cache_key = None
        super().__init__(**kwargs)


    @transaction.atomic
    def post(self, request):
        branch_name = request.query_params.get('branch_name')

        if not branch_name:
            return Response({
                'success': False,
                'status_code': status.HTTP_400_BAD_REQUEST,
                'error': {
                    'code': 'Bad Request',
                    'message': 'branch_name parameter is missing!'
                },
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)



        serializer = self.serializer_class(data=request.data, context={'request': request, 'branch_id': branch_name,})


        serializer.create(validated_data=request.data)
        return Response({
                "status": True,

                "message": "Vendor Expense Added Succesfully"
        }, status=status.HTTP_201_CREATED)



    def get(self, request):
        branch_name = request.query_params.get('branch_name')
        if not branch_name:
            return Response({
                'success': False,
                'status_code': status.HTTP_400_BAD_REQUEST,
                'error': {
                    'code': 'Bad Request',
                    'message': 'branch_name parameter is missing!'
                },
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)


        data = VendorExpense.objects.filter(user=request.user,vendor_branch_id=branch_name)
        serializer = VendorExpenseSerializer_get(data,many=True)





        return Response({
            "status": True,
            "data":serializer.data

        }, status=status.HTTP_200_OK)


    def put(self,request):
        pass
    def delete(self,request):
        pass




