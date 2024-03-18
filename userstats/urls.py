from .views import ExpenseSummaryStats, IncomeSourcesSummaryStats
from django.urls import path

urlpatterns = [
    path('expense_category_data', ExpenseSummaryStats.as_view(),
          name='expense-category-summary'),
          path('income_source_data', IncomeSourcesSummaryStats.as_view(),
          name='income-source-data'),
]