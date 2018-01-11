# -*- coding: utf-8 -*-
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import Select
from selenium.common.exceptions import NoSuchElementException
from selenium.common.exceptions import NoAlertPresentException
import unittest, time, re

class UntitledTestCase(unittest.TestCase):
    def setUp(self):
        self.driver = webdriver.Firefox()
        self.driver.implicitly_wait(30)
        self.base_url = "https://www.katalon.com/"
        self.verificationErrors = []
        self.accept_next_alert = True
    
    def test_untitled_test_case(self):
        driver = self.driver
        driver.get("http://35.225.50.59/login")
        driver.find_element_by_link_text("I need an account").click()
        driver.find_element_by_id("username").click()
        driver.find_element_by_id("username").clear()
        driver.find_element_by_id("username").send_keys("alex")
        driver.find_element_by_id("email").clear()
        driver.find_element_by_id("email").send_keys("alex@test.com")
        driver.find_element_by_id("display-name").clear()
        driver.find_element_by_id("display-name").send_keys("Alex")
        driver.find_element_by_id("first-name").clear()
        driver.find_element_by_id("first-name").send_keys("Alex")
        driver.find_element_by_id("last-name").clear()
        driver.find_element_by_id("last-name").send_keys("Ch")
        driver.find_element_by_id("password").clear()
        driver.find_element_by_id("password").send_keys("12345678")
        driver.find_element_by_id("password-confirm").clear()
        driver.find_element_by_id("password-confirm").send_keys("12345678")
        driver.find_element_by_id("submit").click()
    
    def is_element_present(self, how, what):
        try: self.driver.find_element(by=how, value=what)
        except NoSuchElementException as e: return False
        return True
    
    def is_alert_present(self):
        try: self.driver.switch_to_alert()
        except NoAlertPresentException as e: return False
        return True
    
    def close_alert_and_get_its_text(self):
        try:
            alert = self.driver.switch_to_alert()
            alert_text = alert.text
            if self.accept_next_alert:
                alert.accept()
            else:
                alert.dismiss()
            return alert_text
        finally: self.accept_next_alert = True
    
    def tearDown(self):
        self.driver.quit()
        self.assertEqual([], self.verificationErrors)

if __name__ == "__main__":
    unittest.main()
