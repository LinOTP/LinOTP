# -*- coding: utf-8 -*-
#
#    LinOTP - the open source solution for two factor authentication
#    Copyright (C) 2010 - 2019 KeyIdentity GmbH
#
#    This file is part of LinOTP server.
#
#    This program is free software: you can redistribute it and/or
#    modify it under the terms of the GNU Affero General Public
#    License, version 3, as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the
#               GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#
#    E-mail: linotp@keyidentity.com
#    Contact: www.linotp.org
#    Support: www.keyidentity.com
#

"""
Test caching utils
"""

import unittest
from unittest.mock import DEFAULT, patch

import pytest

from linotp.lib.cache_utils import cache_in_request
from linotp.lib.context import request_context


@pytest.mark.usefixtures("app")
class TestCaching:
    def test_cache_in_request(self):
        """Test if caching values exist in the cache"""
        """
        what might be tested:
        if initialization happens
        different forms of calling the function(to be decorated) still works
        with parameter and without parameter
        """

        def hawaii_pizza(count: int, price: int, param1="foo", param2="bar"):
            """Arbitrary function which gives you a nice pizza with extra toppings
            :param count: count
            :param price: price
            :param param1: topping 1 (optional)
            :param param2: topping 2 (optional)
            """
            # The counter keeps track of how many times the function has been actually called
            if hasattr(hawaii_pizza, "counter"):
                hawaii_pizza.counter += 1
            else:
                hawaii_pizza.counter = 1

            return (
                str(count)
                + " pizzas total each costing "
                + str(price * count)
                + " Euros with "
                + param1
                + "-"
                + param2
                + " extra toppings"
            )

        def hawaii_pizza_keygen(
            count: int, price: int, param1="foo", param2="bar"
        ):
            """Key generator for the hawaii_pizza function
            This function produces a unique key for the input values of hawaii_pizza,
            to make sure the output values would be cached under correct keys.
            The input arguments are exactly the same as the ones of hawaii_pizza function
            """
            key = (count, price, param1, param2)
            return key

        def call_pizzeria_few_times(pizza_maker):
            """just make some pizzas with the pizza_maker function
            two of the outpus are repeated so the caching could be tested
            output [1] = output[5]
            output [4] = output[7]
            Hence in total there are 6 times that the pizza_maker is called uniquely
            """
            output = [None] * 8
            output[0] = pizza_maker(1, 6)  # 1
            output[1] = pizza_maker(
                1, 2, param1="more Ananas", param2="Ananas"
            )  # 2
            output[2] = pizza_maker(
                1, 2, param1="more Ananas", param2="ham"
            )  # 3
            output[3] = pizza_maker(
                1, 2, param1="more Ananas", param2="Ham"
            )  # 4
            output[4] = pizza_maker(
                1, 5, param1="more Ananas", param2="wurst"
            )  # 5
            output[5] = pizza_maker(
                1, 2, param1="more Ananas", param2="Ananas"
            )  # cached
            output[6] = pizza_maker(
                1, 2, param1="Pineapple", param2="Ananas"
            )  # 6
            output[7] = pizza_maker(
                1, 5, param1="more Ananas", param2="wurst"
            )  # cached
            return output

        # (I) First time without the 'key_generator'
        # argument for the 'cache_in_request' decorator.
        # decorating dynamically.
        # Note: this is not the exact equivalent
        # of decorating because we are not changing the reference of the original
        # function being decorated.

        # Keeping the original function undecorated to be used later:
        hawaii_pizza_orig = hawaii_pizza

        # Decorating it with cache_in_request
        hawaii_pizza = cache_in_request(hawaii_pizza)
        hawaii_pizza.counter = 0

        # Calling pizzeria few times:
        outputs_default_keygen = call_pizzeria_few_times(hawaii_pizza)

        # Some of the expected outputs are checked here:
        assert (
            outputs_default_keygen[1]
            == "1 pizzas total each costing 2 Euros with more Ananas-Ananas extra toppings"
        )
        assert (
            outputs_default_keygen[5]
            == "1 pizzas total each costing 2 Euros with more Ananas-Ananas extra toppings"
        )
        assert outputs_default_keygen[4] == outputs_default_keygen[7]

        # we expect that the function is called 6 times and 6 values are stored in cache
        assert hawaii_pizza.counter == 6
        assert len(request_context["hawaii_pizza_cache"]) == 6

        # (II) now testing the decorator with the 'key_generator' argument.

        # Retrieving the original definition of the method
        hawaii_pizza = hawaii_pizza_orig

        # Decorating:
        hawaii_pizza = cache_in_request(key_generator=hawaii_pizza_keygen)(
            hawaii_pizza
        )

        # calling pizzeria few times:
        hawaii_pizza.counter = 0
        request_context["hawaii_pizza_cache"] = {}
        outputs_defined_keygen = call_pizzeria_few_times(hawaii_pizza)

        # Some of the expected outputs are checked here:
        assert (
            outputs_defined_keygen[1]
            == "1 pizzas total each costing 2 Euros with more Ananas-Ananas extra toppings"
        )
        assert (
            outputs_defined_keygen[5]
            == "1 pizzas total each costing 2 Euros with more Ananas-Ananas extra toppings"
        )
        assert outputs_defined_keygen[4] == outputs_defined_keygen[7]

        # we expect that the function is called 6 times and 6 values are stored in cache
        assert hawaii_pizza.counter == 6
        assert len(request_context["hawaii_pizza_cache"]) == 6
