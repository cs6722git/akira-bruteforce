import re #匯入正規表示式（Regular Expression）模組
from playwright.sync_api import Page, expect
#從 Playwright 庫中匯入核心 API。 Page 代表瀏覽器中的一個分頁，是所有自動化操作的主要介面；
#expect 則用於斷言（assertions），即驗證網頁狀態是否符合預期。
import pytest #	匯入 Pytest 測試框架


def create_todo_item(page, todo_text: str): # 定義一個函式，用於在待辦事項應用程式中新增一個待辦事項項目
    page.get_by_role("textbox", name="What needs to be done?").click() # 找到輸入框並點擊它以聚焦
    page.get_by_role("textbox", name="What needs to be done?").fill(todo_text) # 在輸入框中填入待辦事項的文字
    page.get_by_role("textbox", name="What needs to be done?").press("Enter") # 模擬按下 Enter 鍵以提交新增的待辦事項


def test_second_todo_in_list(page: Page):
    # 新增兩個項目到列表
    page.goto("https://demo.playwright.dev/todomvc/#/") # 導航到待辦事項應用程式的網址
    todo_input =  page.get_by_role("textbox", name="What needs to be done?") # 定位到輸入框元素
    expect(page.get_by_test_id("todo-title")).to_contain_text("xxxxx") # 斷言列表中包含特定文字的待辦事項項目
    create_todo_item(page, "test1") # 呼叫函式新增第一個待辦事項
    expect(page.locator("body")).to_contain_text("test1") # 斷言頁面中包含剛新增的待辦事項
    create_todo_item(page, "test2") # 呼叫函式新增第二個待辦事項
    expect(page.locator("body")).to_contain_text("test2") # 斷言列表中第二個待辦事項項目是 "test2

@pytest.fixture
def create_and_check(page: Page): # 定義一個 Pytest 的 fixture，用於在測試前建立並勾選一個待辦事項項目
    page.goto("https://demo.playwright.dev/todomvc/#/") # 導航到待辦事項應用程式的網址
    create_todo_item(page, "test todo") # 呼叫函式新增待辦事項
    page.get_by_role("checkbox", name="Toggle Todo").check() # 勾選待辦事項的核取方塊

# 定義一個測試函式，驗證已勾選的待辦事項是否顯示在「全部」列表中
def test_checked_item_in_all_list(page: Page, create_and_check) -> None: 
    expect(page.get_by_test_id("todo-title")).to_contain_text("test todo") # 斷言頁面中包含已勾選的待辦事項

 # 定義一個測試函式，驗證已勾選的待辦事項是否顯示在「已完成」列表中
def test_checked_item_in_completed_list(page: Page, create_and_check) -> None:
    page.get_by_role("link", name="Completed").click() # 點擊「已完成」連結以切換到已完成的待辦事項列表
    expect(page.get_by_test_id("todo-title")).to_contain_text("test todo") # 斷言頁面中包含已勾選的待辦事項
    # page.get_by_role("link", name="Active").click() # 點擊「Active」連結以切換到未完成的待辦事項列表

 # 定義一個測試函式，驗證已勾選的待辦事項不應顯示在「未完成」列表中
def test_checked_item_not_in_active_list(page: Page, create_and_check) -> None:
    page.get_by_role("link", name="Active").click() # 點擊「未完成」連結以切換到未完成的待辦事項列表    
    # 不顯示
    expect(page.locator("html")).not_to_contain_text("test todo") # 斷言頁面中不包含已勾選的待辦事項

 # 定義一個測試函式，驗證已移除的待辦事項不應顯示在「全部」列表中 
def test_removed_item_not_in_all_list(page: Page, create_and_check) -> None:
    page.get_by_role("button", name="Clear completed").click() # 點擊「清除已完成」按鈕以移除已勾選的待辦事項
    # 不顯示
    expect(page.locator("html")).not_to_contain_text("test todo") # 斷言頁面中不包含已移除的待辦事項

# 定義一個測試函式，驗證已移除的待辦事項不應顯示在「未完成」列表中
def test_removed_item_not_in_active_list(page: Page, create_and_check) -> None:
    page.get_by_role("link", name="Active").click() # 點擊「未完成」連結以切換到未完成的待辦事項列表
    page.get_by_role("button", name="Clear completed").click() # 點擊「清除已完成」按鈕以移除已勾選的待辦事項
    # 不顯示
    expect(page.locator("html")).not_to_contain_text("test todo") # 斷言頁面中不包含已移除的待辦事項

 # 定義一個測試函式，驗證已移除的待辦事項不應顯示在「已完成」列表中
def test_removed_item_not_in_completed_list(page: Page, create_and_check) -> None:
    page.get_by_role("link", name="Completed").click() # 點擊「已完成」連結以切換到已完成的待辦事項列表
    page.get_by_role("button", name="Clear completed").click() # 點擊「清除已完成」按鈕以移除已勾選的待辦事項
    # 不顯示
    expect(page.locator("html")).not_to_contain_text("test todo") # 斷言頁面中不包含已移除的待辦事項

 # 定義一個測試函式，驗證「全部選取」按鈕的功能
def test_check_all_button(page: Page) -> None:
    page.goto("https://demo.playwright.dev/todomvc/#/") # 導航到待辦事項應用程式的網址
    for _ in range(10): # 使用迴圈新增 10 個待辦事項項目
        create_todo_item(page, "test todo") # 呼叫函式新增待辦事項
    page.locator("body > section > div > section > label").click() # 點擊「全部選取」按鈕以勾選所有待辦事項
     # 驗證所有待辦事項項目都已被勾選

    count = 0  # 初始化計數器
     # 遍歷所有待辦事項的核取方塊，驗證它們是否被勾選 # 定位所有待辦事項的核取方塊
    for item_locator in page.locator("xpath=/html/body/section/div/section/ul/li/div/input").all(): 
        expect(item_locator).to_be_checked()  # 斷言該核取方塊已被勾選
        count += 1  # 增加計數器
     # 最後斷言計數器的值應該等於 10
    assert count == 10   # 斷言計數器的值應該等於 10

 # 定義一個測試函式，驗證在存在未勾選項目的情況下，已勾選的待辦事項不會受到「全部選取」按鈕的影響
def test_checked_item_will_not_be_affected_by_check_all_when_unchecked_item_exists(page: Page, create_and_check) -> None:
    create_todo_item(page, "xxxxx")  # 新增另一個待辦事項，保持未勾選狀態
    # 點擊「全部選取」按鈕以嘗試勾選所有待辦事項
    check_all_button = page.locator("body > section > div > section > label")  # 定位「全部選取」按鈕
    check_all_button.click() # 點擊「全部選取」按鈕
    # 驗證已勾選的待辦事項仍然被勾選
    count = 0 # 初始化計數器
    # 遍歷所有待辦事項的核取方塊，驗證已勾選的待辦事項是否仍然被勾選
    for item_locator in page.locator("xpath=/html/body/section/div/section/ul/li/div/input").all():
        expect(item_locator).to_be_checked() # 斷言該核取方塊已被勾選
        count += 1  # 增加計數器
    assert count == 2  # 斷言計數器的值應該等於 2
