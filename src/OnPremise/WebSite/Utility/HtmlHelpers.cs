using System;
using System.Linq;
using System.Linq.Expressions;
using System.Web.Mvc;

namespace Thinktecture.IdentityServer.Web.Utility
{
    public static class HtmlHelpers
    {
        public static MvcHtmlString ValidatorFor<TModel, TValue>(this HtmlHelper<TModel> html, Expression<Func<TModel, TValue>> expression)
        {
            var prop = ModelMetadata.FromLambdaExpression<TModel, TValue>(expression, html.ViewData);
            var name = ExpressionHelper.GetExpressionText(expression);
            return ValidatorInternal(html, name, prop.Description);
        }

        public static MvcHtmlString Validator(this HtmlHelper html, ModelMetadata prop)
        {
            var name = html.ViewData.TemplateInfo.GetFullHtmlFieldName(prop.PropertyName);
            return ValidatorInternal(html, name, prop.Description);
        }
        
        public static MvcHtmlString Validator(this HtmlHelper html, string name, string description = null)
        {
            return ValidatorInternal(html, name, description);
        }

        static MvcHtmlString ValidatorInternal(this HtmlHelper html, string name, string description)
        {
            if (html.ViewData.ModelState.IsValidField(name))
            {
                if (!String.IsNullOrWhiteSpace(description))
                {
                    var help = UrlHelper.GenerateContentUrl("~/Content/Images/help.png", html.ViewContext.HttpContext);
                    TagBuilder img = new TagBuilder("img");
                    img.Attributes.Add("src", help);
                    img.Attributes.Add("title", description);
                    return MvcHtmlString.Create(img.ToString(TagRenderMode.SelfClosing));
                }
            }
            else
            {
                var error = UrlHelper.GenerateContentUrl("~/Content/Images/error.png", html.ViewContext.HttpContext);
                TagBuilder img = new TagBuilder("img");
                img.AddCssClass("error");
                img.Attributes.Add("src", error);
                var title = html.ViewData.ModelState[name].Errors.First().ErrorMessage;
                if (!String.IsNullOrWhiteSpace(description)) title += "\n\n" + description;
                img.Attributes.Add("title", title);
                return MvcHtmlString.Create(img.ToString(TagRenderMode.SelfClosing));
            }

            return MvcHtmlString.Empty;
        }
    }
}