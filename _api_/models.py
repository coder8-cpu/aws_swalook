from django.contrib.auth.models import User
from django.core import validators
from django.db import models
import datetime as dt
import uuid


class SalonBranch(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    vendor_name = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    staff_name = models.CharField(max_length=255)
    branch_name = models.CharField(max_length=255)
    password = models.CharField(max_length=11, blank=True)
    admin_password = models.CharField(max_length=11, blank=True)
    staff_url = models.CharField(max_length=255)
    admin_url = models.CharField(max_length=255)
    minimum_purchase_loyality = models.IntegerField(default=40, null=True)
    class Meta:
        ordering = ['vendor_name']
        verbose_name = "Vendor Branch"

    def __str__(self) -> str:
        return str(self.branch_name)


class SwalookUserProfile(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    salon_name = models.CharField(max_length=255)
    owner_name = models.CharField(max_length=255)
    profile_pic = models.ImageField(blank=True, null=True)
    mobile_no = models.CharField(max_length=10)
    email = models.EmailField(blank=True)
    vendor_id = models.CharField(max_length=6)
    invoice_limit = models.IntegerField(default=0, null=True)
    account_created_date = models.DateField(null=True)
    user_ip = models.CharField(max_length=200, blank=True)
    gst_number = models.CharField(max_length=20, blank=True)
    pan_number = models.CharField(max_length=20, blank=True)
    pincode = models.CharField(max_length=20, blank=True)
    number_of_staff = models.IntegerField(default=0)
    s_gst_percent = models.CharField(max_length=30)
    c_gst_percent = models.CharField(max_length=30)
    current_billslno = models.CharField(max_length=50)
    appointment_limit = models.IntegerField(default=0, null=True)
    invoice_generated = models.IntegerField()
    appointment_generated = models.IntegerField()
    enc_pwd = models.CharField(max_length=400)
    branch_limit = models.IntegerField(default=1, null=True)
    branches_created = models.IntegerField(default=0, null=True)


    class Meta:
        ordering = ['salon_name']
        verbose_name = "Vendor Profile"
        unique_together = [["salon_name", "mobile_no"]]

    def __str__(self):
        return str(self.salon_name)


class VendorLoyalityProgramTypes(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    vendor_branch = models.ForeignKey(SalonBranch, on_delete=models.SET_NULL, null=True)

    program_type = models.CharField(max_length=255)
    price = models.IntegerField()
    expiry_duration =  models.IntegerField()
    points_hold =  models.IntegerField()
    def __str__(self) -> str:
        return str(self.user)





class VendorCustomerLoyalityPoints(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    customer_id = models.CharField(max_length=25555)
    current_customer_points = models.DecimalField(blank=True, null=True, max_digits=6, decimal_places=2)
    issue_date = models.DateField(null=True,blank=True)
    expire_date = models.DateField(blank=True,null=True)
    vendor_branch = models.ForeignKey(SalonBranch, on_delete=models.SET_NULL, null=True)

    class Meta:
        ordering = ['user']
        verbose_name = "Vendor Customers Points"

class VendorCustomers(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    loyality_profile = models.ForeignKey(VendorCustomerLoyalityPoints, on_delete=models.SET_NULL, null=True)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    name = models.CharField(max_length=30,blank=True,null=True)
    mobile_no = models.CharField(max_length=30,blank=True,null=True)
    d_o_b = models.CharField(max_length=30,blank=True,null=True)
    d_o_a = models.CharField(max_length=30,blank=True,null=True)
    

    email = models.CharField(max_length=30,blank=True)
    membership = models.CharField(max_length=30,blank=True,null=True)

    membership_type = models.ForeignKey(VendorLoyalityProgramTypes, on_delete=models.SET_NULL, null=True,)
    vendor_branch = models.ForeignKey(SalonBranch, on_delete=models.SET_NULL, null=True)


    class Meta:
        ordering = ['name']
        verbose_name = "Vendor Customers"

    def __str__(self):
        return f"user {self.name} from branch {self.vendor_branch}"

class VendorService(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, db_index=True)
    service = models.CharField(max_length=30,db_index=True)
    service_price = models.CharField(max_length=30)
    service_duration = models.CharField(max_length=30)

    vendor_branch = models.ForeignKey(SalonBranch, on_delete=models.SET_NULL, null=True,db_index=True)


    class Meta:
        ordering = ['service']
        verbose_name = "Vendor Service"

        indexes = [
            models.Index(fields=['user', 'vendor_branch', 'service']),
        ]

    def __str__(self):
        return str(self.service)





class VendorInvoice(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    slno = models.CharField(max_length=50, blank=True)
    customer_name = models.CharField(max_length=255)
    address = models.CharField(max_length=200, blank=True)
    mobile_no = models.CharField(max_length=10, blank=True)
    email = models.CharField(max_length=50, blank=True)
    services = models.CharField(max_length=40000)
    service_by = models.CharField(max_length=40000)
    total_prise = models.DecimalField(default=0, max_digits=40, decimal_places=2, blank=True)
    total_tax = models.DecimalField(default=0, max_digits=40, decimal_places=2, blank=True)
    total_discount = models.DecimalField(max_digits=40, decimal_places=2, default=0, blank=True)
    time_stamp = models.DateTimeField(null=True, blank=True,auto_now_add=True)
    gst_number = models.CharField(max_length=20, blank=True)
    total_quantity = models.IntegerField(default=0)
    total_cgst = models.DecimalField(default=0, max_digits=40, decimal_places=2, blank=True)
    total_sgst = models.DecimalField(default=0, max_digits=40, decimal_places=2, blank=True)
    grand_total = models.DecimalField(default=0, max_digits=40, decimal_places=2, blank=True)
    vendor_name = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    date = models.DateField()
    month = models.CharField(max_length=30, blank=True)
    week = models.CharField(max_length=30, blank=True)
    year = models.CharField(max_length=30, blank=True)
    vendor_branch = models.ForeignKey(SalonBranch, on_delete=models.SET_NULL, null=True)
    vendor_customers_profile = models.ForeignKey(VendorCustomers, on_delete=models.SET_NULL, null=True)

    comment = models.CharField(max_length=255, blank=True)
    mode_of_payment = models.CharField(max_length=255, blank=True,null=True)
    loyalty_points = models.DecimalField(blank=True, null=True, max_digits=6, decimal_places=2)
    loyalty_points_deducted = models.DecimalField(blank=True, null=True, max_digits=6, decimal_places=2)



    class Meta:
        ordering = ['date']
        verbose_name = "Vendor Invoice"

    def __str__(self):
        return str(self.vendor_name)


class VendorPdf(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    vendor_branch = models.ForeignKey(SalonBranch, on_delete=models.SET_NULL, null=True)
    invoice = models.CharField(max_length=400)
    mobile_no = models.CharField(max_length=255)
    email = models.CharField(max_length=255)
    customer_name = models.CharField(max_length=255)
    file = models.FileField(upload_to="pdf", blank=True, null=True)

    date = models.DateField()
    vendor_email = models.CharField(max_length=255)
    vendor_password = models.CharField(max_length=255)

    class Meta:
        ordering = ['date']
        verbose_name = "Vendor Invoice Pdf"

    def __str__(self):
        return str(self.vendor_branch)


class VendorAppointment(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    vendor_name = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    vendor_branch = models.ForeignKey(SalonBranch, on_delete=models.SET_NULL, null=True)

    customer_name = models.CharField(max_length=255)
    services = models.CharField(max_length=255)

    booking_date = models.CharField(max_length=255)
    date = models.DateField()
    booking_time = models.CharField(max_length=255)
    email = models.CharField(max_length=50)
    mobile_no = models.CharField(max_length=10, blank=True)
    comment = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ['booking_date']
        verbose_name = "Vendor Appointment"

    def __str__(self):
        return str(self.vendor_name)

class VendorStaff(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    vendor_name = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    vendor_branch = models.ForeignKey(SalonBranch, on_delete=models.SET_NULL, null=True)
    staff_name = models.CharField(max_length=400)
    mobile_no = models.CharField(max_length=13, null=True, blank=True)
    staff_role = models.CharField(max_length=400)
    staff_salary_monthly = models.DecimalField(blank=True, null=True, max_digits=10, decimal_places=2)
    base = models.DecimalField(blank=True, null=True, max_digits=10, decimal_places=2)
    house_rent_allownance = models.DecimalField(blank=True, null=True, max_digits=10, decimal_places=2)
    meal_allowance = models.DecimalField(blank=True, null=True, max_digits=10, decimal_places=2)
    incentive_pay = models.DecimalField(blank=True, null=True, max_digits=10, decimal_places=2)
    pf = models.DecimalField(blank=True, null=True, max_digits=10, decimal_places=2)
    staff_slab = models.DecimalField(blank=True, null=True, max_digits=10, decimal_places=2)
    staff_target_business = models.DecimalField(blank=True, null=True, max_digits=10, decimal_places=2)
    staff_commision_cap = models.DecimalField(blank=True, null=True, max_digits=10, decimal_places=2)
    staff_joining_date = models.DateField(blank=True,null=True)
    staff_provident_fund = models.DecimalField(blank=True, null=True, max_digits=10, decimal_places=2)
    staff_professional_tax = models.DecimalField(blank=True, null=True, max_digits=10, decimal_places=2)
    business_of_the_current_month = models.DecimalField(blank=True, null=True, max_digits=10, decimal_places=2, default=0)





class VendorStaffAttendance(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    vendor_name = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    vendor_branch = models.ForeignKey(SalonBranch, on_delete=models.SET_NULL, null=True)
    of_month = models.IntegerField(blank=True,null=True)
    year = models.IntegerField(blank=True,null=True)
    date = models.CharField(max_length=200, blank=True)
    attend = models.BooleanField(default=False,blank=True,null=True)
    leave = models.BooleanField(default=False,blank=True,null=True)
    staff = models.ForeignKey(VendorStaff,on_delete=models.CASCADE,null=True)


class StaffSalary(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    vendor_name = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    vendor_branch = models.ForeignKey(SalonBranch, on_delete=models.SET_NULL, null=True)
    staff = models.ForeignKey(VendorStaff,on_delete=models.CASCADE,null=True)
    of_month = models.IntegerField(blank=True,null=True)
    salary_payble_amount = models.DecimalField(blank=True, null=True, max_digits=10, decimal_places=2)
    business_of_the_month = models.DecimalField(blank=True, null=True, max_digits=10, decimal_places=2)
    year = models.IntegerField(blank=True,null=True)


class StaffSetting(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    vendor_name = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    vendor_branch = models.ForeignKey(SalonBranch, on_delete=models.SET_NULL, null=True)

    number_of_working_days = models.IntegerField()
    signature = models.FileField(upload_to="staff-sign",blank=True,null=True)
    month = models.IntegerField(blank=True,null=True)

class StaffSettingSlab(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    vendor_name = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    vendor_branch = models.ForeignKey(SalonBranch, on_delete=models.SET_NULL, null=True)
    staff_slab = models.DecimalField(blank=True, null=True, max_digits=10, decimal_places=2)
    staff_target_business = models.DecimalField(blank=True, null=True, max_digits=10, decimal_places=2)
    staff_commision_cap = models.DecimalField(blank=True, null=True, max_digits=10, decimal_places=2)



class BusinessAnalysis(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    monthly_analysis = models.ImageField(upload_to="analysis", null=True, blank=True)
    month = models.CharField(max_length=400)

    def __str__(self) -> str:
        return str(self.user)


class HelpDesk(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    first_name = models.CharField(max_length=400)
    last_name = models.CharField(max_length=400)
    email = models.EmailField(max_length=400)
    mobile_no = models.CharField(max_length=400)
    message = models.TextField()

    def __str__(self) -> str:
        return str(self.user)


class VendorInventoryProduct(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    product_id = models.CharField(max_length=400)
    product_name = models.CharField(max_length=400)
    product_price = models.DecimalField(blank=True, null=True, max_digits=10, decimal_places=2)
    product_description = models.TextField()
    vendor_branch = models.ForeignKey(SalonBranch, on_delete=models.SET_NULL, null=True)

    stocks_in_hand = models.IntegerField(default=0)

    unit = models.CharField(max_length=400)
    date = models.DateField()
    month = models.CharField(max_length=30, null=True, blank=True)
    week = models.CharField(max_length=30, null=True, blank=True)
    year = models.CharField(max_length=30, null=True, blank=True)

    def __str__(self) -> str:
        return str(self.product_name)


class VendorInventoryInvoice(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    slno = models.CharField(max_length=400)
    customer = models.ForeignKey(VendorCustomers, on_delete=models.SET_NULL, null=True)
    mobile_no = models.CharField(max_length=13, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    vendor_branch = models.ForeignKey(SalonBranch, on_delete=models.SET_NULL, null=True)

    product = models.ForeignKey(VendorInventoryProduct, on_delete=models.SET_NULL, null=True)
    unit = models.CharField(max_length=255)
    product_price = models.DecimalField(blank=True, null=True, max_digits=10, decimal_places=2)
    product_quantity = models.IntegerField()
    loyalty_points = models.DecimalField(blank=True, null=True, max_digits=6, decimal_places=2)
    loyalty_points_deducted = models.DecimalField(blank=True, null=True, max_digits=6, decimal_places=2)
    total_price = models.DecimalField(default=0, max_digits=10, decimal_places=2, null=True, blank=True)
    total_tax = models.DecimalField(default=0, max_digits=10, decimal_places=2, null=True, blank=True)
    total_discount = models.DecimalField(default=0, max_digits=10, decimal_places=2, null=True, blank=True)
    gst_number = models.CharField(max_length=20, blank=True, null=True)
    total_quantity = models.IntegerField(default=0)
    total_cgst = models.DecimalField(default=0, max_digits=10, decimal_places=2, null=True, blank=True)
    total_sgst = models.DecimalField(default=0, max_digits=10, decimal_places=2, null=True, blank=True)
    grand_total = models.DecimalField(default=0, max_digits=10, decimal_places=2, null=True, blank=True)
    date = models.DateField()
    month = models.CharField(max_length=30, null=True, blank=True)
    week = models.CharField(max_length=30, null=True, blank=True)
    year = models.CharField(max_length=30, null=True, blank=True)

    def __str__(self) -> str:
        return str(self.product)


class VendorCustomerLoyalityLedger(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    vendor_branch = models.ForeignKey(SalonBranch, on_delete=models.SET_NULL, null=True)

    customer = models.ForeignKey(VendorCustomerLoyalityPoints, on_delete=models.SET_NULL, null=True)
    point_spend = models.IntegerField()
    point_available = models.IntegerField()
    point_gain = models.IntegerField()
    invoice_obj = models.CharField(max_length=400)
    inventory_invoice_obj = models.CharField(max_length=400)
    date = models.DateField()
    month = models.CharField(max_length=30, null=True, blank=True)
    week = models.CharField(max_length=30, null=True, blank=True)
    year = models.CharField(max_length=30, null=True, blank=True)

    def __str__(self) -> str:
        return str(self.user)

class VendorExpenseCategory(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    vendor_branch = models.ForeignKey(SalonBranch, on_delete=models.SET_NULL, null=True)
    vendor_expense_type = models.CharField(max_length=400)

    def __str__(self) -> str:
        return str(vendor_expense_type)

class VendorExpense(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    vendor_branch = models.ForeignKey(SalonBranch, on_delete=models.SET_NULL, null=True)
    expense_type = models.CharField(max_length=4000,null=True, blank=True)
    inventory_item = models.CharField(max_length=4000,null=True, blank=True)
    expense_account = models.CharField(max_length=4000,null=True, blank=True)
    expense_category = models.ManyToManyField(VendorExpenseCategory,blank=True,null=True)
    expense_amount = models.DecimalField(default=0, max_digits=10, decimal_places=2, null=True, blank=True)
    invoice_id = models.CharField(max_length=4000,null=True, blank=True)
    date = models.DateField()
    month = models.CharField(max_length=30, null=True, blank=True)
    week = models.CharField(max_length=30, null=True, blank=True)
    year = models.CharField(max_length=30, null=True, blank=True)
    comment = models.CharField(max_length=30, null=True, blank=True)







