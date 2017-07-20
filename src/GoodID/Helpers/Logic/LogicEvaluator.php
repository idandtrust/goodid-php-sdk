<?php
/**
 * Copyright 2017 ID&Trust, Ltd.
 *
 * You are hereby granted a non-exclusive, worldwide, royalty-free license to
 * use, copy, modify, and distribute this software in source code or binary form
 * for use in connection with the web services and APIs provided by ID&Trust.
 *
 * As with any software that integrates with the GoodID platform, your use
 * of this software is subject to the GoodID Terms of Service
 * (https://goodid.net/docs/tos).
 * This copyright notice shall be included in all copies or substantial portions
 * of the software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

namespace GoodID\Helpers\Logic;

use GoodID\Exception\GoodIDException;
use JWadhams\JsonLogic;

/**
 * An evaluator for the JsonLogic expressions used in rules and essential/conditional
 *
 * @link http://jsonlogic.com JsonLogic
 */
class LogicEvaluator
{
    /**
     * The rules that are recognizable by this evaluator
     *
     * @var array
     */
    private $rules;

    /**
     * The cache storing the results of rules
     *
     * @var array
     */
    private $ruleResultCache;

    /**
     * The data parameters
     *
     * @var array
     */
    private $data;

    /**
     * Constructs a LogicEvaluator class with the given rules and data
     *
     * @param array $rules Rules defined by the RP
     * @param array $data Data parameters
     */
    public function __construct(array $rules, array $data)
    {
        $this->rules = $rules;
        $this->data = $data;
    }

    /**
     * Evaluates the given expression which can be:
     * - A value of a primitive type => It is returned unchanged
     * - A JsonLogic expression => It is evaluated and the result is returned
     * - A GoodID rule reference => The result of the corresponding rule is returned
     *
     * @param mixed $expr Expression
     *
     * @return mixed Result
     *
     * @throws GoodIDException on error
     */
    public function evaluate($expr)
    {
        if (is_array($expr)) {
            $referencedRuleName = $this->getReferencedRuleName($expr);

            return !is_null($referencedRuleName)
                ? $this->evaluateRule($referencedRuleName)
                : $this->evaluateExpression($expr);
        }

        return $expr;
    }

    /**
     * Get referenced rule name if any
     *
     * @param array $expr Expression
     *
     * @return string|null Rule Name
     */
    private function getReferencedRuleName(array $expr)
    {
        if (isset($expr['var'])
            && is_string($expr['var'])
            && strlen($expr['var']) >= 1
            && $expr['var'][0] === '$'
        ) {
            return $expr['var'];
        }

        return null;
    }

    /**
     * Evaluate rule
     *
     * @param string $ruleName
     *
     * @return mixed Result
     *
     * @throws GoodIDException on error
     */
    private function evaluateRule($ruleName)
    {
        if (!isset($this->rules[$ruleName])) {
            throw new GoodIDException('Undefined rule: ' . $ruleName);
        }

        // isset would not work for null array elements
        if (!array_key_exists($ruleName, $this->ruleResultCache)) {
            $this->ruleResultCache[$ruleName] = $this->evaluateExpression($this->rules[$ruleName]);
        }

        return $this->ruleResultCache[$ruleName];
    }

    /**
     * Evaluate expression
     *
     * @param mixed $expr Expression
     *
     * @return mixed Result
     */
    private function evaluateExpression($expr)
    {
        return JsonLogic::apply($expr, $this->data);
    }
}
