import zipfile
import os
import uuid
from rest_framework import viewsets, status
from .models import *
from .serializers import *
from rest_framework import views, generics, response, permissions, authentication
from rest_framework.response import Response
from rest_framework.decorators import action
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.contrib.auth import login, logout
from django.conf import settings
from rest_framework.permissions import IsAuthenticated
from .permissions import *
from .paginations import *
from rest_framework import filters
from .filters import *
from django_filters.rest_framework import DjangoFilterBackend
from django.utils.decorators import method_decorator
from rest_framework.parsers import FileUploadParser, FormParser, MultiPartParser
from rest_framework.parsers import FileUploadParser, FormParser,MultiPartParser
from .AI import *
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
# Create your views here.

class CsrfExemptSessionAuthentication(authentication.SessionAuthentication):
    def enforce_csrf(self, request):
        return

class expAIViewSet(viewsets.ModelViewSet):
    """
    This viewset automatically provides `list`, `create`, `retrieve`,
    `update` and `destroy` actions.

    Additionally we also provide an extra `checkBody` action.
    """
    queryset = Softwarelibs.objects.all()
    serializer_class = SoftwareLibsSerializer


@method_decorator(name="list", decorator=swagger_auto_schema(manual_parameters=[openapi.Parameter('datasetName', openapi.IN_QUERY, description='Tên bộ dữ liệu', type=openapi.TYPE_STRING)
    ,openapi.Parameter('datasetSumFrom', openapi.IN_QUERY, description='Cận dưới số lượng', type=openapi.TYPE_INTEGER),
    openapi.Parameter('datasetSumTo', openapi.IN_QUERY, description='Cận trên số lượng', type=openapi.TYPE_INTEGER),
    openapi.Parameter('datasetOwner', openapi.IN_QUERY, description='ID người tạo', type=openapi.TYPE_INTEGER),
    openapi.Parameter('datasetProb', openapi.IN_QUERY, description='Bài toán áp dụng', type=openapi.TYPE_INTEGER)]))
class DatasetsViewSet(viewsets.ModelViewSet):
    """
    This viewset automatically provides `list`, `create`, `retrieve`,
    `update` and `destroy` actions.

    Additionally we also provide an extra `checkBody` action.
    """
    authentication_classes = (CsrfExemptSessionAuthentication,)
    serializer_class = DatasetsSerializer
    permission_classes = [IsOwner | IsAdmin]
    pagination_class = LargeResultsSetPagination
    datasetname = openapi.Parameter(
        'datasetname', openapi.IN_QUERY, description='Tên bộ dữ liệu', type=openapi.TYPE_STRING)
    # filter_backends = [DatasetsFilter]
    # search_fields = ['datasetname', 'datasetfolderurl','datasettraining','datasettesting','datasetsum','datasetcreator','datasetdescription']
    # filter_fields = ['datasetname', 'datasetfolderurl','datasettraining','datasettesting','datasetsum','datasetcreator','datasetdescription']

    def get_queryset(self):
        usr = self.request.user
        usr = User.objects.get(email=usr.email)
        if usr.roleid.rolename == "ADMIN":
            queryset = Datasets.objects.all()
        elif usr.roleid.rolename == "STUDENT":
            queryset = Datasets.objects.filter(
                datasettype=1) | Datasets.objects.filter(datasetowner=self.request.user)
        else:
            usrclass = list(usr.usrclass.all())
            student = [list(i.user_set.all()) for i in usrclass]
            student = sum(student, [])
            queryset = Datasets.objects.filter(
                datasettype=1) | Datasets.objects.filter(datasetowner__in=student)
        datasetname = self.request.query_params.get('datasetname')
        datasetProb = self.request.query_params.get('datasetProb')
        datasetSumTo = self.request.query_params.get('datasetSumTo')
        datasetSumFrom = self.request.query_params.get('datasetSumFrom')
        datasetOwner = self.request.query_params.get('datasetOwner')
        queryset = queryset.filter(datasetsum__lte=datasetSumTo) if datasetSumTo !=None else queryset
        queryset = queryset.filter(datasetsum__gte=datasetSumFrom) if datasetSumFrom !=None else queryset
        queryset = queryset.filter(datasetproblem=datasetProb) if datasetProb !=None else queryset
        queryset = queryset.filter(datasetowner=datasetOwner) if datasetOwner !=None else queryset
        queryset = queryset.filter(datasetname__icontains=datasetname) if datasetname !=None else queryset
        return queryset

    def perform_create(self, serializer):
        serializer.save(datasetowner=self.request.user)

    def destroy(self, request, *args, **kwargs):
        try:
            instance = self.get_object()

            import shutil
            shutil.rmtree(f'datasets/{instance.datasetfolderurl}')
            self.perform_destroy(instance)
        except:
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(status=status.HTTP_204_NO_CONTENT)


class AccountsViewSet(viewsets.ModelViewSet):
    """
    This viewset automatically provides `list`, `create`, `retrieve`,
    `update` and `destroy` actions.

    Additionally we also provide an extra `checkBody` action.
    """
    # permission_classes = (IsAdmin,)
    queryset = User.objects.all()
    pagination_class = LargeResultsSetPagination
    serializer_class = UserSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ['email', 'name']
    authentication_classes = (CsrfExemptSessionAuthentication,)
    def perform_destroy(self, instance):
        instance.is_active = False
        instance.save()
    def update(self, request, *args, **kwargs):
        from django.contrib.auth.hashers import (
    make_password,
)
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        request.data["password"]=make_password(request.data["password"])
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if getattr(instance, '_prefetched_objects_cache', None):
            # If 'prefetch_related' has been applied to a queryset, we need to
            # forcibly invalidate the prefetch cache on the instance.
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)
class ChangeUserPasswordView(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = ChangePassword2Serializer

    def get_object(self, queryset=None):
        id_user = self.request.data.get('id_user')
        obj = self.queryset.get(id=id_user)
        return obj

    def update(self, request):
        """
        Change User's Password API
        """
        obj = self.get_object()
        new_password = request.data.get('new_password')
        obj.set_password(new_password)
        obj.save()
        return Response({"result": "Success"})




class LoginView(generics.CreateAPIView):
    serializer_class = LoginSerializer
    permission_classes = (permissions.AllowAny,)
    authentication_classes = (CsrfExemptSessionAuthentication,)

    @swagger_auto_schema(tags=['Đăng nhập - Đăng ký'])
    def post(self, serializer):
        serializer = LoginSerializer(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        login(self.request, user)
        return response.Response(UserSerializer(user).data)


class LogoutView(views.APIView):
    authentication_classes = (CsrfExemptSessionAuthentication,)
    @swagger_auto_schema(tags=['Đăng nhập - Đăng ký'])
    def post(self, request):
        logout(request)
        return response.Response()


@method_decorator(name="post", decorator=swagger_auto_schema(tags=["Đăng nhập - Đăng ký"]))
class RegisterView(generics.CreateAPIView):
    serializer_class = UserSerializer
    permission_classes = (permissions.AllowAny,)

    @swagger_auto_schema(tags=['Đăng nhập - Đăng ký'])
    def perform_create(self, serializer):
        serializer.is_staff=False
        user = serializer.save()
        user.backend = settings.AUTHENTICATION_BACKENDS[0]
        login(self.request, user)


class ChangePasswordView(generics.UpdateAPIView):
    authentication_classes = (CsrfExemptSessionAuthentication,)
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    @swagger_auto_schema(tags=['Đăng nhập - Đăng ký'])
    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangeNameView(generics.UpdateAPIView):
    """
    An endpoint for changing name.
    """
    serializer_class = ChangeNameSerializer
    model = User
    permission_classes = (IsAuthenticated,)
    authentication_classes = (CsrfExemptSessionAuthentication,)
    def get_object(self, queryset=None):
        obj = self.request.user
        obj = User.objects.get(id=obj.pk)
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check password
            if not self.object.check_password(serializer.data.get("password")):
                return Response({"password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.name = serializer.data.get("name")
            # self.object.usrclass.set(serializer.data.get("usrclass"))
            self.object.usrdob = serializer.data.get("usrdob")
            self.object.usrfullname = serializer.data.get("usrfullname")
            self.object.usrfaculty = serializer.data.get("usrfaculty")

            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Infor updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    lookup_field = 'pk'
    authentication_classes = (CsrfExemptSessionAuthentication,)
    def get_object(self, *args, **kwargs):
        return self.request.user
    # # permission_classes = [permissions.IsAuthenticatedOrReadOnly]
    # # permission_classes = [permissions.IsAuthenticatedOrReadOnly,
    # #                       IsOwnerOrReadOnly]
    # test_param1 = openapi.Parameter('check_type', openapi.IN_QUERY, description="height or width", type=openapi.TYPE_STRING)
    # test_param2 = openapi.Parameter('id', openapi.IN_QUERY, description="id of expAI", type=openapi.TYPE_NUMBER)
    # user_response = openapi.Response('response description', StudientSerializer)

    # @swagger_auto_schema(method='get', manual_parameters=[test_param1, test_param2], responses={404: 'Not found', 200:'ok', 201:StudientSerializer})
    # @action(methods=['GET'], detail=False, url_path='check-body')
    # def check_body(self, request):
    #     """
    #     Check body API
    #     """
    #     check_type = request.query_params.get('check_type')
    #     id = request.query_params.get('id')

    #     print(check_type, id)
    #     obj = self.queryset.get(id=id)
    #     rs = ""
    #     if check_type == 'height':
    #         if obj.height > 1:
    #             rs = "tall"
    #         else:
    #             rs = "short"
    #     else:
    #         if obj.weight > 1:
    #             rs = "fat"
    #         else:
    #             rs = "thin"
    #     return Response({"result": rs})

    # @action(methods=['POST'], detail=False)
    # def echo(self, request):
    #     # deserializer
    #     obj = StudientSerializer(request.data)
    #     print(obj)
    #     # serializer
    #     return Response(obj.data)

    # @action(methods=['GET'], detail=False)
    # def find_by_name(self, request):
    #     name = request.query_params.get('name')
    #     print(self.queryset)
    #     objs = expAI.objects.filter(name__exact=name)
    #     return Response(StudientSerializer(objs).data)


class ExperimentsViewSet(viewsets.ModelViewSet):
    model = Experiments
    queryset = Experiments.objects.all()
    serializer_class = ExperimentsSerializer
    authentication_classes = (CsrfExemptSessionAuthentication,)
    pagination_class = LargeResultsSetPagination
    permission_classes = [IsOwnerExp | IsAdmin]
    authentication_classes = (CsrfExemptSessionAuthentication,)

    def list(self, request, *args, **kwargs):
        '''
        List all items
        '''
        if request.user.id == None:
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        usr = request.user
        usr = User.objects.get( id = usr.pk)

        if usr.roleid.rolename=="ADMIN":
            queryset=Experiments.objects.all()
        elif usr.roleid.rolename=="STUDENT":
            queryset  = Experiments.objects.filter(expcreatorid = usr.id)
        else:#giao vien
            usrclass= list(usr.usrclass.all())
            student = [list(i.user_set.all())  for i in usrclass]
            student = sum(student,[])
            queryset = Experiments.objects.filter(expcreatorid__in = student) | Experiments.objects.filter(expcreatorid = usr.id)
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page,many = True)
            return self.get_paginated_response(serializer.data)
        serializer = ExperimentsSerializer(queryset, many=True)
        return Response(serializer.data)
    def create(self, request, *args, **kwargs):


            if request.user.id == None:
                return Response(status=status.HTTP_401_UNAUTHORIZED)
            serializer = ExperimentsSerializer(data=request.data)
            if serializer.is_valid():
                myexp = serializer.save()
                myexp.expcreatorid = request.user
                myexp.save()
                serializer = ExperimentsSerializer(myexp,many=False)
                return Response(serializer.data,status=status.HTTP_201_CREATED)

#                return JsonResponse({
#                    'message': 'Create a new exp successful!'
#                }, status=status.HTTP_201_CREATED)

            return JsonResponse({
                'message': 'Create a new exp unsuccessful!'
            }, status=status.HTTP_400_BAD_REQUEST)

    # @swagger_auto_schema(method='get',manual_parameters=[],responses={404: 'Not found', 200:'ok', 201:ExperimentsSerializer})
    # @action(methods=['GET'], detail=False, url_path='get-list-exps')
    # def get_list_exps(self, request):
    #     """
    #     lay ds bai thi nghiem theo id user
    #     """
    #     if request.user.id == None:
    #         return Response(status=status.HTTP_401_UNAUTHORIZED)
    #     usr = request.user
    #     usr = User.objects.get( id = usr.pk)

    #     if usr.roleid.rolename=="ADMIN":
    #         queryset=Experiments.objects.all()
    #     elif usr.roleid.rolename=="STUDENT":
    #         queryset  = Experiments.objects.filter(expcreatorid = usr.id)
    #     else:#giao vien
    #         usrclass= list(usr.usrclass.all())
    #         student = [list(i.user_set.all())  for i in usrclass]
    #         student = sum(student,[])
    #         queryset = Experiments.objects.filter(expcreatorid__in = student) | Experiments.objects.filter(expcreatorid = usr.id)

    #     serializer = ExperimentsSerializer(queryset, many=True)
    #     return Response(serializer.data)

    id_softlib = openapi.Parameter('id_softlib',openapi.IN_QUERY,description='id cua softlib',type=openapi.TYPE_NUMBER)
    @swagger_auto_schema(method='get',manual_parameters=[id_softlib],responses={404: 'Not found', 200:'ok', 201:ModelsSerializer})
    @action(methods=['GET'], detail=False, url_path='get-list-models')
    def get_list_models(self, request):

        """
        lay ds model theo id softlib
        """
        if request.user.id == None:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        id_softlib = request.query_params.get('id_softlib')

        models = Models.objects.filter(modelsoftlibid = id_softlib)
        serializer = ModelsSerializer(models,many=True)

        return Response(serializer.data)

    #id_softlib = openapi.Parameter('id_softlib',openapi.IN_QUERY,description='id cua softlib',type=openapi.TYPE_NUMBER)
    @swagger_auto_schema(method='get',manual_parameters=[id_softlib],responses={404: 'Not found', 200:'ok', 201:DatasetsSerializer})
    @action(methods=['GET'], detail=False, url_path='get-list-dataset')
    def get_list_datasets(self, request):
        if request.user.id == None:
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        usr = self.request.user
        usr = User.objects.get(email=usr.email)

        id_softlib = request.query_params.get('id_softlib')

        if usr.roleid.rolename=="ADMIN":
            queryset=Datasets.objects.all()
        elif usr.roleid.rolename=="STUDENT":
            queryset = Datasets.objects.filter(datasettype=1,datasetsoftID__pk = id_softlib)|Datasets.objects.filter(datasetowner = self.request.user,datasetsoftID__pk = id_softlib)
        else:#giao vien
            usrclass= list(usr.usrclass.all())
            student = [list(i.user_set.all())  for i in usrclass]
            student = sum(student,[])
            queryset = Datasets.objects.filter(datasettype=1,datasetsoftID__pk = id_softlib)|Datasets.objects.filter(datasetowner__in = student,datasetsoftID__pk = id_softlib)

        serializer = DatasetsSerializer(queryset,many=True)

        return Response(serializer.data)
    id_model = openapi.Parameter('id_model',openapi.IN_QUERY,description='id model',type=openapi.TYPE_NUMBER)
    @swagger_auto_schema(method='get',manual_parameters=[id_model],responses={404: 'Not found', 200:'ok', 201:ModelsSerializer})
    @action(methods=['GET'], detail=False, url_path='get-default-parameters')
    def get_default_parameters(self, request):

        """
        set-parameters
        """
        if request.user.id == None:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        id_model = request.query_params.get('id_model')

        models = Models.objects.get(modelid = id_model)
        serializer = ModelsSerializer(models,many =False)

        return Response(serializer.data)





    #start - stop train
    id_exp = openapi.Parameter('id_exp',openapi.IN_QUERY,description='id cua exp',type=openapi.TYPE_NUMBER)
    paramsconfigs_json = openapi.Parameter('paramsconfigs_json',openapi.IN_QUERY,description='json string paramsconfig',type=openapi.TYPE_STRING)
    id_paramsconfigs = openapi.Parameter('id_paramsconfigs',openapi.IN_QUERY,description='id cua bang paramsconfig',type=openapi.TYPE_NUMBER)

    @swagger_auto_schema(manual_parameters=[id_exp, paramsconfigs_json],responses={404: 'Not found', 200:'ok'})
    @action(methods=['GET'], detail=False, url_path='start-train')
    def start_train(self, request):

        """
        start train
        """
        if request.user.id == None:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        # user = request.user
        # user = User.objects.get( id = user.pk)

        id_exp = request.query_params.get('id_exp')
        paramsconfigs_json = request.query_params.get('paramsconfigs_json')
        print(paramsconfigs_json)


        if check_json_file(paramsconfigs_json):

            exp = Experiments.objects.get(expid = id_exp)
            paramsconfigs = Paramsconfigs(jsonstringparams=paramsconfigs_json,trainningstatus=1,configexpid=exp)
            paramsconfigs.save()
            id_params = paramsconfigs.pk

            #--------------------
            # thread
            import threading
            t = threading.Thread(target=trainning_process, args=(id_params,), kwargs={})
            t.setDaemon(True)
            t.start()
            #--------------------


            serializer = ParamsconfigsSerializer(paramsconfigs,many = False)


            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return JsonResponse({
                'message': 'Có một số lỗi với chuỗi json được nhập!'
            },status=status.HTTP_400_BAD_REQUEST)
            #return Response(status=status.HTTP_400_BAD_REQUEST)





    @swagger_auto_schema(manual_parameters=[id_paramsconfigs],responses={404: 'Not found', 200:'ok'})
    @action(methods=['GET'], detail=False, url_path='stop-train')
    def stop_train(self, request):

        """
        stop train
        """
        if request.user.id == None:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        user = request.user
        user = User.objects.get( id = user.pk)

        id_exp = request.query_params.get('id_exp')
        id_paramsconfigs = request.query_params.get('id_paramsconfigs')

        exp = Experiments.objects.filter(expid = id_exp)
        paramsconfigs = Paramsconfigs.objects.get(configid = id_paramsconfigs)
        paramsconfigs.trainningstatus = 0
        paramsconfigs.save()
        _results = Trainningresults.objects.filter(configid = paramsconfigs).order_by('trainresultid').last()
        serializer = TrainningresultsSerializer(_results,many = False)

        return Response(serializer.data, status=status.HTTP_200_OK)

    @swagger_auto_schema(method='get',manual_parameters=[id_paramsconfigs],responses={404: 'Not found', 200:'ok', 201:ResultsSerializer})
    @action(methods=['GET'], detail=False, url_path='get-all-traning-results')
    def get_all_traning_results(self, request):

        """
        get trainning results
        """
        if request.user.id == None:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        # user = request.user
        # user = User.objects.get( id = user.pk)

        # id_exp = request.query_params.get('id_exp')
        id_paramsconfigs = request.query_params.get('id_paramsconfigs')

        # exp = Experiments.objects.filter(expid = id_exp)
        paramsconfigs = Paramsconfigs.objects.get(configid = id_paramsconfigs)
        queryset = Trainningresults.objects.filter(configid = paramsconfigs).order_by('trainresultid')

        serializer = TrainningresultsSerializer(queryset,many = True)
        return Response(serializer.data)



    pre_result_index = openapi.Parameter('pre_result_index',openapi.IN_QUERY,description='index của bản ghi trước đó, nếu gọi lần đầu thì để là 0',type=openapi.TYPE_NUMBER)
    @swagger_auto_schema(method='get',manual_parameters=[id_paramsconfigs,pre_result_index],responses={404: 'Not found', 200:'ok', 201:ResultsSerializer})
    @action(methods=['GET'], detail=False, url_path='get-new-traning-result')
    def get_new_traning_result(self, request):

        """
        get new trainning results
        """
        if request.user.id == None:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        # user = request.user
        # user = User.objects.get( id = user.pk)

        # id_exp = request.query_params.get('id_exp')
        id_paramsconfigs = request.query_params.get('id_paramsconfigs')
        pre_result_index = request.query_params.get('pre_result_index')

        # exp = Experiments.objects.filter(expid = id_exp)
        paramsconfigs = Paramsconfigs.objects.get(configid = id_paramsconfigs)
        _results = Trainningresults.objects.filter(configid = paramsconfigs,trainresultindex__gt = pre_result_index).order_by('trainresultindex')

        if _results:
            queryset = _results
            serializer = TrainningresultsSerializer(queryset,many = True)
            response = {
                    'status': 'success',
                    'code': status.HTTP_201_CREATED,
                    'message': 'Data uploaded successfully',
                    'data': {'result':serializer.data,'status':paramsconfigs.trainningstatus}
                }
            return Response(response,status=status.HTTP_200_OK)
        else:
            return JsonResponse({
                        'message': 'Chưa có result mới!'
                    },status=status.HTTP_102_PROCESSING)


    id_dataset = openapi.Parameter('id_dataset',openapi.IN_QUERY,description='id cua dataset test',type=openapi.TYPE_NUMBER)
    id_paramsconfigs = openapi.Parameter('id_paramsconfigs',openapi.IN_QUERY,description='id cua bang paramsconfig',type=openapi.TYPE_NUMBER)

    @swagger_auto_schema(manual_parameters=[id_dataset, id_paramsconfigs],responses={404: 'Not found', 200:'ok',201:ResultsSerializer})
    @action(methods=['GET'], detail=False, url_path='start-test')
    def start_test(self, request):

        """
        start_test
        """
        if request.user.id == None:
            return Response(status=status.HTTP_401_UNAUTHORIZED)


        id_dataset = request.query_params.get('id_dataset')
        id_paramsconfigs = request.query_params.get('id_paramsconfigs')
        _dataset = Datasets.objects.get(pk = id_dataset)
        _paramsconfigs = Paramsconfigs.objects.get(pk = id_paramsconfigs)
        _result = Results()
        _result.resultconfigid = _paramsconfigs
        _result.resulttestingdataset = _dataset
        _result.save()
        #----------------------------------- thread
        import threading
        t = threading.Thread(target=testing_process, args=(_result.pk,), kwargs={})
        t.setDaemon(True)
        t.start()
        #-------------------------------------------------------------------
        serializer = ResultsSerializer(_result,many = False)
        return Response(serializer.data, status=status.HTTP_201_CREATED)



    id_test_result = openapi.Parameter('id_test_result',openapi.IN_QUERY,description='id test result nhan khi gọi API start test',type=openapi.TYPE_NUMBER)
    @swagger_auto_schema(manual_parameters=[id_test_result,],responses={404: 'Not found', 200:'ok',201:ResultsSerializer})
    @action(methods=['GET'], detail=False, url_path='get-test-result')
    def get_test_result(self, request):
        if request.user.id == None:
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        id_test_result = request.query_params.get('id_test_result')
        _result = Results.objects.get(pk = id_test_result)
        if _result.resultaccuracy:
            serializer = ResultsSerializer(_result,many = False)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            serializer = ResultsSerializer(_result,many = False)
            return Response(serializer.data, status=status.HTTP_200_OK)


    input_path1 = openapi.Parameter('input_path1',openapi.IN_QUERY,description='đường dẫn tới folder input',type=openapi.TYPE_STRING)
    input_path2 = openapi.Parameter('input_path2',openapi.IN_QUERY,description='đường dẫn tới folder ảnh người trong face Recognition',type=openapi.TYPE_STRING)
    data_type = openapi.Parameter('data_type',openapi.IN_QUERY,description='image/video',type=openapi.TYPE_STRING)
    @swagger_auto_schema(manual_parameters=[id_paramsconfigs,input_path1,input_path2,data_type],responses={404: 'Not found', 200:'ok',201:PredictSerializer})
    @action(methods=['GET'], detail=False, url_path='predict')
    def predict(self,request):
        if request.user.id == None:
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        input_path1 = request.query_params.get('input_path1')
        input_path2 = request.query_params.get('input_path2')
        data_type = request.query_params.get('data_type')
        id_paramsconfigs = request.query_params.get('id_paramsconfigs')

        _para = Paramsconfigs.objects.get(pk = id_paramsconfigs)
        _predict = Predict()
        _predict.configid = _para
        _predict.inputpath = input_path1
        if input_path2:
            _predict.inputpath2 = input_path2
        _predict.datatype = data_type
        _predict.save()

        import threading
        t = threading.Thread(target=predict_process, args=(_predict.pk,), kwargs={})
        t.setDaemon(True)
        t.start()

        serializer = PredictSerializer(_predict,many = False)
        return Response(serializer.data, status=status.HTTP_200_OK)

    id_predict = openapi.Parameter('id_predict',openapi.IN_QUERY,description='id predict',type=openapi.TYPE_NUMBER)
    @swagger_auto_schema(manual_parameters=[id_predict],responses={404: 'Not found', 200:'ok',201:PredictSerializer})
    @action(methods=['GET'], detail=False, url_path='get_predict_result')
    def get_predict_result(self,request):
        if request.user.id == None:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        id_predict = request.query_params.get('id_predict')

        _predict = Predict.objects.get(pk = id_predict)
        list_result = os.listdir(_predict.outputpath)
        serializer = PredictSerializer(_predict,many = False)
        if len(list_result) > 0:
            response = {
                    'status': 'success',
                    'code': status.HTTP_201_CREATED,
                    'message': 'Predict successfully',
                    'data': {'result':list_result,'data':serializer.data}
                }
        else:
            response = {
                    'status': 'success',
                    'code': status.HTTP_201_CREATED,
                    'message': 'Output is Null',
                    'data': {'result':list_result,'data':serializer.data}
                }

        return Response(response, status=status.HTTP_200_OK)




        
        
        



    


import zipfile
import uuid
import os
class DatasetsUploadView(views.APIView):
    parser_classes = [FormParser,MultiPartParser]
    authentication_classes = (CsrfExemptSessionAuthentication,)
    # @swagger_auto_schema(tags=['datasets'])
    @swagger_auto_schema(
            operation_id='Upload zip',
            operation_description='Upload zip',
            operation_summary="Upload file zip cho bạn Hiếu",
            manual_parameters=[
                openapi.Parameter('file', openapi.IN_FORM, type=openapi.TYPE_FILE, description='Zip to be uploaded'),

            ],
tags=['datasets']
        )
    def post(self, request):
        file_obj = request.data['file']
        new_name = uuid.uuid4()

        with zipfile.ZipFile(file_obj, mode='r', allowZip64=True) as file:

            directory_to_extract = f"datasets/{new_name}"
            file.extractall(directory_to_extract)

        response = {
            'status': 'success',
            'code': status.HTTP_201_CREATED,
            'message': 'Data uploaded successfully',
            'data': new_name
        }
        return Response(response)

class ModelsViewSet(viewsets.ModelViewSet):
    queryset = Models.objects.all()
    serializer_class = ModelsSerializer
    permission_classes = [IsOwner , IsAdmin]
    def perform_create(self, serializer):
        serializer.save(modelowner=self.request.user)
    
    id_user = openapi.Parameter('id_user',openapi.IN_QUERY,description='id cua giao vien',type=openapi.TYPE_NUMBER)
    @swagger_auto_schema(method='get',manual_parameters=[id_user],responses={404: 'Not found', 200:'ok', 201:ModelsSerializer})
    @action(methods=['GET'], detail=False, url_path='get-list-models')
    def get_list_models(self, request):

        """
        lay ds model theo id giao vien
        """
        if request.user.id == None:
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        id_user = request.query_params.get('id_user')

        models = Models.objects.filter(modelcreator = id_user)
        serializer = ModelsSerializer(models,many=True)

        return Response(serializer.data)

    def get_permissions(self):
        if self.action == 'get_list_model':
            permission_classes = [IsStudent|IsTeacher|IsAdmin]
        else:
            permission_classes = [IsTeacher]

        return [permission() for permission in permission_classes]

        
class ModelsUploadView(views.APIView):
    parser_classes = [FormParser,MultiPartParser]
    permission_classes = [IsTeacher]

    def post(self, request):
        file_obj = request.data['file']
        new_name = uuid.uuid4()
        
        with zipfile.ZipFile(file_obj, mode='r', allowZip64=True) as file:
            
            directory_to_extract = f"models/{new_name}"
            file.extractall(directory_to_extract)

        response = {
                    'status': 'success',
                    'code': status.HTTP_201_CREATED,
                    'message': 'Data uploaded successfully',
                    'data': new_name
                }
        return Response(response)

class FileUploadView(views.APIView):
    
    parser_classes = [FormParser,MultiPartParser]


    @swagger_auto_schema(
            operation_id='Upload file',
            operation_description='Upload file',
            operation_summary="Upload a file",
            manual_parameters=[openapi.Parameter('file', openapi.IN_FORM, type=openapi.TYPE_FILE, description='file to be uploaded'),], tags=['experiment']
        )
    def post(self, request):
        file_obj = request.FILES['file']
        new_name = uuid.uuid4()
        path = f"./static/predict_data/{new_name}/"
        if not os.path.exists(path):
            os.makedirs(path)
        with open(path + file_obj.name, 'wb+') as destination:
            for chunk in file_obj.chunks():
                destination.write(chunk)
        response = {
                    'status': 'success',
                    'code': status.HTTP_201_CREATED,
                    'message': 'Data uploaded successfully',
                    'data': path
                }
        return Response(response)
class FilesUploadView(views.APIView):
    
    parser_classes = [FormParser,MultiPartParser]


    @swagger_auto_schema(
            operation_id='Upload files',
            operation_description='Upload files',
            operation_summary="Upload file files",
            manual_parameters=[openapi.Parameter('file', openapi.IN_FORM, type=openapi.TYPE_FILE, description='files to be uploaded'),], tags=['experiment']
        )
    def post(self, request):
        new_name = uuid.uuid4()
        path = f"./static/predict_data/{new_name}/"
        if not os.path.exists(path):
            os.makedirs(path)



        for file_obj in request.FILES.getlist("files"):

            with open(path + file_obj.name, 'wb+') as destination:
                for chunk in file_obj.chunks():
                    destination.write(chunk)
        response = {
                    'status': 'success',
                    'code': status.HTTP_201_CREATED,
                    'message': 'Data uploaded successfully',
                    'data': path
                }
        return Response(response)


#fuctions for thread

def trainning_process(para_id):
    import time
    print("train started")
    print(para_id)
    for i in range(1,10):
        time.sleep(10)
        _para = Paramsconfigs.objects.get(pk=para_id)
        if _para.trainningstatus == 0:
            _new_result = Trainningresults()
            _new_result.configid = _para
            _new_result.accuracy = i
            _new_result.lossvalue = 100-1
            _new_result.trainresultindex = i
            _new_result.is_last = True
            _new_result.save()
            return
            break

        else:
            _new_result = Trainningresults()
            _new_result.configid = _para
            _new_result.accuracy = i
            _new_result.lossvalue = 100-1
            _new_result.trainresultindex = i
            _new_result.is_last = False
            _new_result.save()
    _para = Paramsconfigs.objects.get(pk=id)
    _para.trainningstatus = 0
    _para.save()
    
    print("train finished")

    return
def testing_process(result_id):
    import time
    print("test started")
    print(result_id)
    _result  = Results.objects.get(pk=result_id)
    _result.resultaccuracy = 0.98
    _result.resultdetail = '/somethings.txt'
    time.sleep(20)
    _result.save()
    print("test finished")

def predict_process(pre_id):
    import time
    import cv2
    print("test started")
    print(pre_id)
    

    _pre  = Predict.objects.get(pk=pre_id)

    result_path = str(_pre.inputpath)[:9] + 'predict_result' + str(_pre.inputpath)[21:]
    if not os.path.exists(result_path):
        os.makedirs(result_path)
    
    if _pre.datatype == 'image':
        for filename in os.listdir(str(_pre.inputpath)):
            img = cv2.imread(os.path.join(str(_pre.inputpath),filename))
            if img is not None:
                img = cv2.flip(img,0)
                cv2.imwrite(os.path.join(result_path,filename),img)
        # _pre.outputpath = result_path
        # _pre.save()
    elif _pre.datatype == 'video':
        # _pre.outputpath = result_path
        # _pre.save()
        return
        # for filename in os.listdir(str(_pre.inputpath)):
        #     video = cv2.VideoCapture(os.path.join(str(_pre.inputpath),filename))
        #     if video.isOpened() == False:
        #         _pre.details = "Error reading video file"
        #         return
        #     frame_width = int(video.get(3))
        #     frame_height = int(video.get(4))
            
        #     size = (frame_width, frame_height)
        #     result = cv2.VideoWriter(os.path.join(result_path,filename), 
        #                  cv2.VideoWriter_fourcc(*'MJPG'),
        #                  10, size)
            



    _pre.accuracy = 0.98
    _pre.details = '/somethings.txt'
    _pre.outputpath =  result_path
    #time.sleep(20)
    _pre.save()
    print("test finished")

